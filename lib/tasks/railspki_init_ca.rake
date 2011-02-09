desc 'Init RailsPKI CA Instance'

task "railspki:init_ca" => :environment do
  ActiveRecord::Base.establish_connection
  
  print "Initialize CA...\n"
  print " - Tag Instance as CA_INSTANCE..."
  inst=PKIInstance.new
  inst.name="RailsPKI CA"
  inst.instance=PKIInstance::CA_INSTANCE
  inst.save
  print "done\n"
  
  print " - Create Root CA..."
  params=Hash.new
  params["ca_domain_id"]=0
  params["yaml"]=File.open("#{RAILS_ROOT}/config/CA/RailsRootCA.yaml", "r").readlines.to_s
  ca_root=CaDomain.new(params)
  ca_root.pubkey_pem=File.open("#{RAILS_ROOT}/config/CA/RailsRootCA.crt", "r").readlines.to_s if File.exists?("#{RAILS_ROOT}/config/CA/RailsRootCA.crt")
  ca_root.privkey_pem=File.open("#{RAILS_ROOT}/config/CA/RailsRootCA.key", "r").readlines.to_s if File.exists?("#{RAILS_ROOT}/config/CA/RailsRootCA.key")
  ca_root.save
  File.open("config/ssl/rails_root_ca.crt", "w") do |f|
    f.write(ca_root.pubkey_pem)
  end
  print "done\n"
  
  print " - Create PKI Root CA..."
  params=Hash.new
  params["ca_domain_id"]=ca_root.id
  params["yaml"]=File.open("#{RAILS_ROOT}/config/CA/RailsPKIRootCA.yaml", "r").readlines.to_s
  ca_pki_root=CaDomain.new(params)
  ca_pki_root.save
  File.open("config/ssl/rails_pki_root_ca.crt", "w") do |f|
    f.write(ca_pki_root.pubkey_pem)
  end
  print "done\n"
  
  print " - Create PKI Webserver CA..."
  params=Hash.new
  params["ca_domain_id"]=ca_pki_root.id
  params["yaml"]=File.open("#{RAILS_ROOT}/config/CA/RailsPKIWebserverCA.yaml", "r").readlines.to_s
  ca_pki_ws=CaDomain.new(params)
  ca_pki_ws.save
  File.open("config/ssl/rails_pki_webserver_ca.crt", "w") do |f|
    f.write(ca_pki_ws.pubkey_pem)
  end
  print "done\n"
  
  print " - Create PKI Client CA..."
  params=Hash.new
  params["ca_domain_id"]=ca_pki_root.id
  params["yaml"]=File.open("#{RAILS_ROOT}/config/CA/RailsPKIClientCA.yaml", "r").readlines.to_s
  ca_pki_client=CaDomain.new(params)
  ca_pki_client.save
  File.open("config/ssl/rails_pki_client_ca.crt", "w") do |f|
    f.write(ca_pki_client.pubkey_pem)
  end
  print "done\n"
  
  print " - Insert Auth Method Rheoli PKI Client Cert..."
  a=AuthMethod.new
  a.name="Auth with Rheoli PKI Client CA Cert"
  a.meth={
    :type => "client_cert",
    :check => {
      :issuer_dn  => "/CN=Rails PKI Client CA/OU=PKI/O=RailsPKI/L=Zurich/ST=Zurich/C=CH"
    }
  }
  a.save
  print "done\n"
  
  print " - Insert Auth Method User Password..."
  a=AuthMethod.new
  a.name="Auth with Password"
  a.meth={
    :type => "user_password"
  }
  a.save
  print "done\n"

end