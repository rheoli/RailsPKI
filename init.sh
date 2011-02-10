rm db/railspki_dev.db3
rm -f config/ssl/*.crt
rm -f config/ssl/users/*
rake db:migrate
rake railspki:ca:init
rake railspki:ca:create_server_cert
rake railspki:ca:create_user
