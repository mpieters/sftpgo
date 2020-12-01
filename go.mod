module github.com/drakkan/sftpgo

go 1.14

require (
	github.com/GehirnInc/crypt v0.0.0-20200316065508-bb7000b8a962
	github.com/alexedwards/argon2id v0.0.0-20200802152012-2464efd3196b
	github.com/eikenb/pipeat v0.0.0-20200430215831-470df5986b6d
	github.com/go-chi/chi v1.5.0
	github.com/go-chi/render v1.0.1
	github.com/go-sql-driver/mysql v1.5.0
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/lib/pq v1.8.0
	github.com/mattn/go-sqlite3 v1.14.5
	github.com/otiai10/copy v1.2.0
	github.com/pires/go-proxyproto v0.3.2
	github.com/pkg/sftp v1.12.1-0.20201118115123-7230c61342c8
	github.com/prometheus/client_golang v1.8.0
	github.com/rs/xid v1.2.1
	github.com/rs/zerolog v1.20.0
	github.com/spf13/cobra v1.1.1
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.6.1
	go.etcd.io/bbolt v1.3.5
	go.uber.org/automaxprocs v1.3.0
	golang.org/x/crypto v0.0.0-20201124201722-c8d3bf9c5392
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b
	golang.org/x/sys v0.0.0-20201201145000-ef89a241ccb3
	gopkg.in/natefinch/lumberjack.v2 v2.0.0

)

replace golang.org/x/crypto => github.com/drakkan/crypto v0.0.0-20201118124913-1ba5185435c1
