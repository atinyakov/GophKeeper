# GophKeeper

GophKeeper is a secure client-server system for storing private secrets: login-password pairs, text notes, card data, and binary files. The server uses mutual TLS (mTLS) for authentication, and clients communicate over a secure HTTPS connection.

## Features

* Encrypted storage of secrets
* mTLS-based authentication
* Secrets are synchronized automatically in background
* CLI client with REPL shell and agent mode
* Server-side user registration and authentication

---

## 📦 Server Setup

### Requirements

* Go 1.20+
* PostgreSQL 12+

### 1. Clone the repository

```bash
git clone https://github.com/atinyakov/GophKeeper.git
cd GophKeeper
```

### 2. Generate TLS certificates

```bash
go run ./tools/certgen/main.go
```

This generates a self-signed CA and client/server certificates under `./certs`.

### 3. Prepare PostgreSQL database

Create a new database and user:

```sql
CREATE USER gophkeeper_user WITH PASSWORD 'gophkeeper_pass';
CREATE DATABASE gophkeeper_db OWNER gophkeeper_user;
```

### 4. Run the server

```bash
go run ./cmd/server \
  -d "host=localhost port=5432 user=gophkeeper_user password=gophkeeper_pass dbname=gophkeeper_db sslmode=disable"
```

---

## 🧑 Client Usage

### 1. Build the client

```bash
go build -ldflags "-X main.version=$(date +%Y%m%d) -X main.buildDate=$(date -I)" -o gophkeeper ./cmd/client
```

### 2. Register a new user

```bash
./gophkeeper -cmd=register -login=alice -url=https://localhost:8080 -ca=certs/ca.crt
```

This will generate and save `client.crt` and `client.key`.

### 3. Start shell mode (REPL)

```bash
./gophkeeper -cmd=shell -url=https://localhost:8080 -cert=client.crt -key=client.key -ca=certs/ca.crt
```

### Available Commands in REPL

```
add              Add a new secret interactively
list             List all secrets
get <id>         Show details of a secret
edit <id>        Modify a secret
delete <id>      Delete a secret
exit             Exit the shell
```

---

## 🧾 Build Metadata

The client binary supports showing build version and date via:

```bash
./gophkeeper -version
```

---

