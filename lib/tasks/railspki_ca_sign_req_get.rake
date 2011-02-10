desc 'RailsPKI CA Get Sign Requests'

require 'net/https'
require 'uri'
 
task "railspki:ca:sign:req:get" => :environment do
  ActiveRecord::Base.establish_connection
  ActionWebService::API::Base.allow_active_record_expects=true

  log=[]
  RaServer.find_all.each do |rs|
    if rs.name=="-local-"
      ra_sign=RaItem.find(:all, :conditions=>["state like ?", RaItem::STATE_SIGN_APPROVED])
    else
      server=rs.ca_item.dn["CN"]
      o=ActionWebService::Client::Soap.new(BackendApi, "https://#{server}:4443/backend/api")
      ra_sign=o.find_to_sign
    end

    ra_sign.each do |ri|
      if CaItem.create_from_ra_item(rs.id, ri)!=nil
        log<<"#{rs.name}: #{ri.dn} added"
        ri.state=RaItem::STATE_IN_SIGNING
        ri.save
      end
    end
  end

end
