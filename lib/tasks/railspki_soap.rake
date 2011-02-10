desc 'RailsPKI SOAP Test'

task "railspki:soap" => :environment do
  ActiveRecord::Base.establish_connection
  ActionWebService::API::Base.allow_active_record_expects=true

  FULL=true 

  soap={"CaDomain"=>{}}

  Role.find(:all).each do |role|
    next if role.ra_server.ca_item.nil?
    next if role.users.nil?
    next if role.auth_methods.nil?

    print "Parse role #{role.to_name}:\n"
    server=role.ra_server.id
    soap[server]={"User"=>{}, "AuthMethod"=>{}, "Role"=>{}, "CaDomain"=>nil} if soap[server].nil?
    print " - for server #{server}\n"
    soap[server]["Role"][role.id]=[role.attributes, [], []]
    cas=role.ca_domain
    while !cas.nil?
      soap["CaDomain"][cas.id]=1
      cas=cas.ca_domain
    end
    role.users.each do |user|
      print "  - user #{user.username}\n"
      soap[server]["User"][user.id]=[user.attributes, nil, nil]
      soap[server]["Role"][role.id][1]<<user.id
    end
    role.auth_methods.each do |am|
      print "  - am #{am.name}\n"
      soap[server]["AuthMethod"][am.id]=[am.attributes, nil, nil]
      soap[server]["Role"][role.id][2]<<am.id
    end
  end

  soap.each do |ra_id, data|
    next if ra_id=="CaDomain"
    ra_server=RaServer.find_by_id(ra_id)
    server=ra_server.ca_item.dn["CN"]
    o=ActionWebService::Client::Soap.new(BackendApi, "https://#{server}:4443/backend/api")

    print "Checking Class CaDomain:\n"
    update=[]
    soap["CaDomain"].each do |did,count|
      attr=CaDomain.find_by_id(did).attributes
      attr["privkey_pem"]="-none-"
      update<<attr.to_yaml
    end
    print " - Update CaDomain...\n"
    o.update_entries("CaDomain", update) if update.size>0

    links_a=[]
    links_u=[]
    [User, AuthMethod, Role].each do |type_c|
      print "Checking Class #{type_c.name}:\n"
      res=o.find_update(type_c.name)
      res_h={}
      res.each do |r|
        res_h[r.id]=[1, r.updated_on]
      end
      data[type_c.name].each do |id, attr|
        if !res_h[id].nil?
          if !res_h[id][1].nil? and res_h[id][1]<attr[0]["updated_on"]
            res_h[id][0]=2
          else
            res_h[id][0]=3
          end
        else
          res_h[id]=[0, 0]
        end
      end
      update=[]
      delete=[]
      res_h.each do |id, attr|
        print " - entry #{id}: "
        print "Add" if attr[0]==0
        print "Delete" if attr[0]==1
        print "Update" if attr[0]==2
        print "Up-to-date" if attr[0]==3
        print "\n"
        if attr[0]==0 or attr[0]==2 or FULL
          obj=data[type_c.name][id][0]
          ["role_id", "auth_method_id", "user_id"].each do |id_id|
            obj.delete(id_id) if obj.has_key?(id_id)
          end
          update<<obj.to_yaml
          if type_c==Role
            r=Role.find_by_id(id)
            links_u[id]=[] if links_u[id].nil?
            links_a[id]=[] if links_a[id].nil?
            r.users.each do |u|
              links_u[id]<<u.id
            end
            r.auth_methods.each do |a|
              links_a[id]<<a.id
            end
          end
        end
        delete<<id if attr[0]==1
      end
      p delete
      o.update_entries(type_c.name, update) if update.size>0
      o.delete_entries(type_c.name, delete) if delete.size>0
    end
    0.upto(links_u.size-1) do |id|
      next if links_u[id].nil? or links_a[id].nil?
      o.role_links(id, links_u[id]||[], links_a[id]||[])
    end
  end
end
