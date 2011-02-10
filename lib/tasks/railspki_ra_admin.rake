desc 'RailsPKI RA Admin Tests'

require 'net/https'
require 'uri'
 
task "railspki:ra_admin" => :environment do
  store=OpenSSL::X509::Store.new
  store.add_cert(::OpenSSL::X509::Certificate.new(File.read(RAILS_ROOT + "/config/ssl/rails_pki_client_ca.crt")))
  store.add_cert(::OpenSSL::X509::Certificate.new(File.read(RAILS_ROOT + "/config/ssl/rails_pki_webserver_ca.crt")))
  store.add_cert(::OpenSSL::X509::Certificate.new(File.read(RAILS_ROOT + "/config/ssl/rails_pki_root_ca.crt")))
  store.add_cert(::OpenSSL::X509::Certificate.new(File.read(RAILS_ROOT + "/config/ssl/rails_root_ca.crt")))
  http = Net::HTTP.new(RailsPKI::Config[:ca_ip], 3443)
  http.use_ssl = true
  http.key=OpenSSL::PKey::RSA.new(File.new("config/ssl/users/stephan.key"))
  http.cert=OpenSSL::X509::Certificate.new(File.new("config/ssl/users/stephan.crt"))
  http.cert_store=store
  http.verify_mode=OpenSSL::SSL::VERIFY_NONE
  http.start {
    http.request_get("/ra_admin/get_last_update_from_cadomain") {|res|
      print res.body
      v7=OpenSSL::PKCS7::PKCS7.new(res.body)
      p v7.verify(
            [OpenSSL::X509::Certificate.new(File.read(RAILS_ROOT+"/config/ssl/users/stephan.crt"))],
            store)
      p v7.error_string
      p v7.data
      yaml=YAML.load(v7.data)
      p yaml
    }
  }
end