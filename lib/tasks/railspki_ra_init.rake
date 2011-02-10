desc 'Init RailsPKI RA Instance'

task "railspki:ra:init" => :environment do
  ActiveRecord::Base.establish_connection
  
  if RailsPKI::Config[:type]!="RA"
    print " -> Error no RA !!!\n"
    exit
  end
  
  web_privkey=OpenSSL::PKey::RSA.new(2048)
  web_req=OpenSSL::X509::Request.new
  web_dn=Array.new
  web_dn << ["CN", "hostname", OpenSSL::ASN1::PRINTABLESTRING]
  web_req.version   =0
  web_req.subject   =OpenSSL::X509::Name.new(web_dn)
  web_req.public_key=web_privkey.public_key
  web_req.sign(web_privkey, OpenSSL::Digest::SHA1.new)
  File.open("config/ssl/server.key", "w") do |f|
    f.write(web_privkey.to_pem)
  end
  File.open("config/ssl/server.req", "w") do |f|
    f.write(web_req.to_pem)
  end
  
  print "done\n"
end
