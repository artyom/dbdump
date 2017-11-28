// Command dbdump saves contents of tables in a given MySQL database to
// per-table CSV files with optional gzip compression.
//
// dbdump saves either specified or all database tables which are readable by
// the connected user; if only subset of table columns is readable, only these
// readable columns are saved.
//
// By default program concurrenlty reads multiple tables over multiple
// connections (see -n flag), if consistency between dumped tables is required,
// use -tx flag to save them sequentially in a single transaction.
//
// MySQL credentials (user and password) are read from the "client" section of
// the .my.cnf file which is expected to have the following format:
//
// 	[client]
// 	user = username
// 	password = password
//
// If -tls flag is used, program connects to the server over TLS and expects
// server certificate to be signed with certificate authority from the system CA
// pool. On UNIX systems the environment variables SSL_CERT_FILE and
// SSL_CERT_DIR can be used to override the system default locations for the SSL
// certificate file and SSL certificate files directory, respectively.
//
// When running in concurrent mode, program only returns when all tables are
// processed reporting the first encountered error. When running in a single
// transaction mode (-tx flag), program terminates on the first error right
// away.
//
// Only database, table and column names that can be used as unquoted MySQL
// identifiers are supported — they are only allowed to contain characters from
// [A-Za-z0-9_] range.
//
// Null values are saved in CSV as NULL.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/artyom/autoflags"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/sync/errgroup"
)

func main() {
	args := &runArgs{
		Dir:   "out",
		Creds: filepath.Join(os.Getenv("HOME"), ".my.cnf"),
		N:     runtime.GOMAXPROCS(-1),
	}
	autoflags.Parse(args)
	if err := run(args, flag.Args()...); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type runArgs struct {
	DB     string `flag:"db,database name"`
	Addr   string `flag:"addr,database host:port"`
	Dir    string `flag:"dir,directory to store csv files"`
	Creds  string `flag:"mycnf,path to .my.cnf file to read user/password from"`
	NoGzip bool   `flag:"nogzip,do not compress files"`
	Tx     bool   `flag:"tx,dump all tables sequentially in a single transaction"`
	TLS    bool   `flag:"tls,use TLS"`
	N      int    `flag:"n,allow n tables to be dumped simultaneously"`
}

func (a *runArgs) Check() error {
	if a.Addr == "" {
		return fmt.Errorf("empty addr")
	}
	if !validName(a.DB) {
		return fmt.Errorf("invalid database name")
	}
	return nil
}

func run(args *runArgs, tables ...string) error {
	if err := args.Check(); err != nil {
		return err
	}
	user, pass, err := parseMyCNF(args.Creds)
	if err != nil {
		return err
	}
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s", user, pass, args.Addr, args.DB) +
		"?maxAllowedPacket=0&readTimeout=5m&writeTimeout=5m"
	if args.TLS {
		dsn += "&tls=true"
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	if len(tables) == 0 {
		tables, err = dbTables(db, args.DB)
		if err != nil {
			return err
		}
	}
	for _, name := range tables {
		if !validName(name) {
			return fmt.Errorf("table name %q cannot be used as unquoted MySQL identifier", name)
		}
	}
	if args.Tx {
		tx, err := db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
		if err != nil {
			return err
		}
		defer tx.Rollback()
		for _, name := range tables {
			file := filepath.Join(args.Dir, name+".csv")
			if !args.NoGzip {
				file += ".gz"
			}
			if err := dumpToFile(tx, !args.NoGzip, args.DB, name, user, file); err != nil {
				return err
			}
		}
		return nil
	}
	if args.N < 1 {
		args.N = 1
	}
	gate := make(chan struct{}, args.N)
	var g errgroup.Group
	for _, name := range tables {
		file := filepath.Join(args.Dir, name+".csv")
		if !args.NoGzip {
			file += ".gz"
		}
		name := name // explicitly shadow variable to be captured by closure
		g.Go(func() error {
			gate <- struct{}{}
			defer func() { <-gate }()
			return dumpToFile(db, !args.NoGzip, args.DB, name, user, file)
		})
	}
	return g.Wait()
}

// dumpToFile creates file, optionally sets up a gzip compression to it and then
// calls dumpTable to dump table contents into it.
func dumpToFile(db dbQ, useGzip bool, database, table, user, file string) error {
	dir := filepath.Dir(file)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := ioutil.TempFile(dir, ".temp-"+table)
	if err != nil {
		return err
	}
	defer f.Close()
	defer os.Remove(f.Name())
	var w io.Writer = f
	var gw *gzip.Writer
	if useGzip {
		if gw, err = gzip.NewWriterLevel(f, gzip.BestSpeed); err != nil {
			return err
		}
		w = gw
	}
	if err := dumpTable(w, db, database, table, user); err != nil {
		return err
	}
	if gw != nil {
		if err := gw.Close(); err != nil {
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), file)
}

// dumpTable verifies whether user has access to select from the table and dumps
// all allowed to select columns as a CSV into w.
func dumpTable(w io.Writer, db dbQ, database, table, user string) error {
	colSpec := "*"
	var discard int
	query := `select 1 from information_schema.table_privileges where privilege_type="SELECT"
		and table_schema=? and table_name=? and INSTR(grantee, ?)=1`
	err := db.QueryRow(query, database, table, "'"+user+"'").Scan(&discard)
	switch err {
	case nil: // guaranteed to have explicit select privilege on table
		goto doDump
	case sql.ErrNoRows: // either we have implicit privileges OR only per-column privileges
	default:
		return err
	}
	if cols, err := selectableColumns(db, database, table); err != nil {
		return err
	} else if len(cols) > 0 {
		for _, name := range cols {
			if !validName(name) {
				return fmt.Errorf("column name %q of table %q cannot be used as unquoted MySQL identifier", name, table)
			}
		}
		colSpec = strings.Join(cols, ",")
	}
doDump:
	rows, err := db.Query("SELECT " + colSpec + " from " + table)
	if err != nil {
		return err
	}
	defer rows.Close()
	var hasHdr bool
	var vals []string
	var ptrs []interface{}
	out := csv.NewWriter(w)
	defer out.Flush()
	for rows.Next() {
		if !hasHdr {
			names, err := rows.Columns()
			if err != nil {
				return err
			}
			if err := out.Write(names); err != nil {
				return err
			}
			vals = make([]string, len(names))
			ptrs = make([]interface{}, len(names))
			for i := range ptrs {
				ptrs[i] = &sql.NullString{}
			}
			hasHdr = true
		}
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		for i, v := range ptrs {
			v := v.(*sql.NullString)
			switch {
			case v.Valid:
				vals[i] = v.String
			default:
				vals[i] = "NULL"
			}
		}
		if err := out.Write(vals); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	out.Flush()
	return out.Error()
}

// selectableColumns returns list of readable columns for the given table as
// read from the information_schema.columns table.
func selectableColumns(db dbQ, database, table string) ([]string, error) {
	query := `select column_name from information_schema.columns
		where table_schema=? and table_name=? order by ordinal_position`
	rows, err := db.Query(query, database, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	var s string
	for rows.Next() {
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// dbTables returns list of tables in a given database
func dbTables(db *sql.DB, name string) ([]string, error) {
	rows, err := db.Query("select table_name from information_schema.tables where table_schema=?", name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	var s string
	for rows.Next() {
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// readDSN parses .my.cnf and returns found user and password
func parseMyCNF(name string) (user, password string, err error) {
	f, err := os.Open(name)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var clientSection bool
	for sc.Scan() {
		b := sc.Bytes()
		if len(b) == 0 || b[0] == '#' {
			continue
		}
		if b[0] == '[' {
			clientSection = bytes.HasPrefix(b, []byte("[client]"))
			continue
		}
		if !clientSection {
			continue
		}
		bb := bytes.SplitN(b, []byte("="), 2)
		if len(bb) != 2 {
			continue
		}
		switch key := string(bytes.TrimSpace(bb[0])); key {
		case "user":
			user = string(bytes.TrimSpace(bb[1]))
		case "password":
			password = string(bytes.TrimSpace(bb[1]))
		}
	}
	if err := sc.Err(); err != nil {
		return "", "", err
	}
	if user == "" || password == "" {
		return "", "", fmt.Errorf("either user or password not found in %q", name)
	}
	return user, password, nil
}

// validName returns whether s is a valid name that can be used as unquoted
// MySQL identifier. It only returns true on non-empty strings containing
// characters in range [A-Za-z0-9_].
func validName(s string) bool {
	if s == "" {
		return false
	}
	// https://dev.mysql.com/doc/refman/5.6/en/identifiers.html
	for _, r := range s {
		switch {
		case '0' <= r && r <= '9':
		case 'A' <= r && r <= 'Z':
		case 'a' <= r && r <= 'z':
		case r == '_':
		default:
			return false
		}

	}
	return true
}

// dbQ describes common methods of sql.DB and sql.Tx used by this program
type dbQ interface {
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
}

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] [table1 table2 ...]\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}
}

//go:generate sh -c "go doc >README"
