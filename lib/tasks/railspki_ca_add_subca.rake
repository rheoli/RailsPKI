desc 'Init RailsPKI CA Instance'

task "railspki:ca:add:subca" => :environment do
  ActiveRecord::Base.establish_connection

  inst=PKIInstance.find_by_instance(PKIInstance::CA_INSTANCE)
  if inst.nil?
    print " -> Error no CA !!!\n"
    exit
  end

  ca=CaDomain.find_by_name("Rails Root CA")
  if ca.nil?
    print " -> Error CA 'Rails Root CA' not found (-> run init_ca first) !!!\n"
    exit
  end
  
  print " - Create Rails Code Sign CA..."
  params=Hash.new
  params["ca_domain_id"]=ca.id
  params["yaml"]=File.open("#{RAILS_ROOT}/config/CA/RailsCodeSignCA.yaml", "r").readlines.to_s
  ca_pki_root=CaDomain.new(params)
  ca_pki_root.save
  File.open("config/ssl/codesign_ca.crt", "w") do |f|
    f.write(ca_pki_root.pubkey_pem)
  end
  print "done\n"
  
end
