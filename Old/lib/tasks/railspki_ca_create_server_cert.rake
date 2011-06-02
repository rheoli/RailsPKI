desc 'Create Webserver Cert for RailsPKI'

task "railspki:ca:create_server_cert" => :environment do
  ActiveRecord::Base.establish_connection
  
  print "Create Webserver Cert for RailsPKI...\n"
  
  if RailsPKI::Config[:type]!="CA"
    print " -> Error no CA !!!\n"
    exit
  end
  
  ca=CaDomain.find_by_name("Rails PKI Webserver CA")
  if ca.nil?
    print " -> Error CA 'Rails PKI Webserver CA' not found (-> run init_ca first) !!!\n"
    exit
  end
  
  print " Enter fqdn hostname: "
  srv_host=STDIN.gets.chomp
  print " Enter cert password: "
  srv_passwd=STDIN.gets.chomp
  
  print " - Generate Server Cert..."
  ra_req = RaReqgen.new 
  params={"CN"=>srv_host, "OU"=>"CA Admin", "bits"=>"2048", "password"=>srv_passwd, "password_confirmation"=>srv_passwd}
  ra_req.add_params(ca.id, params)
  if ra_req.valid?
    c_pkey, c_req = ra_req.gen_request
    File.open("config/ssl/server.key", "w") do |f|
      f.write(c_pkey)
    end
    params.delete("bits")
    params.delete("password")
    params.delete("password_confirmation")
    ra_item=RaItem.new(:ca_domain_id=>ca.id, :csr=>c_req.to_pem)
    ra_item.dn=params
    ra_item.save
    ra_item.ready_to_sign!
    ra_item.approved!
    ca_item=CaItem.create_from_ra_item(0, ra_item)
    ra_item.in_signing_process!
    ca_item.sign_and_save
    ra_item_n=RaItem.update_ra_item(ca_item)
    File.open("config/ssl/server.crt", "w") do |f|
      f.write(ra_item_n.crt_pem)
    end
  else
    p ra_req
    print "Error to create cert\n"
    exit
  end
  print "done\n"
end
