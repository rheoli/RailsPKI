desc 'RailsPKI CA Get Sign Requests'

require 'net/https'
require 'uri'
 
task "railspki:ca:sign:req:get" => :environment do
  ActiveRecord::Base.establish_connection
  ActionWebService::API::Base.allow_active_record_expects=true

  log=[]
  RaServer.find(:all).each do |rs|
    if rs.name=="-local-"
      ra_sign=RaItem.find_in_state(:all, :sign_approved)
    else
      server=rs.ca_item.dn["CN"]
      o=ActionWebService::Client::Soap.new(BackendApi, "https://#{server}/pki/backend/api")
      begin
        ra_sign=o.find_to_sign
      rescue
        print "Warning: Can't connect to #{server}\n"
        ra_sign={}
      end
    end

    ra_sign.each do |ri|
      _ri=ri
      if ri.class!=RaItem
        _ri=YAML.load(ri)
      end
      if CaItem.create_from_ra_item(rs.id, _ri)!=nil
        log<<"#{rs.name}: #{_ri["dn"]} added"
        if ri.class==RaItem
          ri.in_signing_process!
          ri.save
        else
          t=o.set_item_state(_ri["id"], "in_signing_process")
p t
        end
      end
    end
    
    if rs.name=="-local-"
      RaRevoke.find(:all).each do |rev|
        ca_item=CaItem.find_by_ra_item_id(rev.ra_item_id)
        next if ca_item.nil?
        ca_rev=CaRevoke.find_by_ca_item_id(ca_item.id, :conditions=>["updated_on < ?", rev.updated_on])
        if !ca_rev.nil?
          ca_rev.reason=rev.reason
          ca_rev.user_id=rev.user_id
          ca_rev.save
        else
          ca_rev=CaRevoke.new
          ca_rev.reason=rev.reason
          ca_rev.user_id=rev.user_id
          ca_rev.ca_item_id=ca_item.id
          ca_rev.save
        end
      end
    end
  end
  print "Logging:\n"
  log.each do |l|
    print " - #{l}\n"
  end
end
