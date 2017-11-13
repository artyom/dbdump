package main

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/csv"
	"fmt"
	"io"
	"os"

	"github.com/artyom/autoflags"
	_ "github.com/go-sql-driver/mysql"
)

func main() {
	args := struct {
		DB   string `flag:"db,database name"`
		Addr string `flag:"addr,database host:port"`
	}{}
	autoflags.Parse(&args)
	if err := run(os.Stdout, args.Addr, args.DB); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(w io.Writer, addr, dbname string) error {
	if dbname == "" {
		return fmt.Errorf("empty db name")
	}
	if addr == "" {
		return fmt.Errorf("empty addr")
	}
	user, pass, err := parseMyCNF(os.ExpandEnv("$HOME/.my.cnf"))
	if err != nil {
		return err
	}
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/%s", user, pass, addr, dbname))
	if err != nil {
		return err
	}
	defer db.Close()
	rows, err := db.Query("SELECT * from users limit 10")
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

// readDSN parses .my.cnf and user and password
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
