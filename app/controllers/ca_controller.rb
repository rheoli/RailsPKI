#--
# Copyright (c) 2006 Stephan Toggweiler
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#++

class CaController < ApplicationController
  layout "ca"
  
  before_filter :authorize_ca

 protected

   def authorize_ca
     return if !authorize

     role=Role.find_by_id(session[:role])
     redirect_to_access_denied("no role defined") and return if role.nil?

     return if role.name==Role::ROLE_CA_ADMIN

     redirect_to_access_denied("not enough privileges")
   end

 protected
 
  def view_template(_class)
    if !params[:id].nil?
      @db_view = _class.find_by_id(params[:id]) || _class.new
    else
      @db_views=_class.find(:all)
      return(true)
    end
    false
  end

  def view_templates(_class)
    @db_views=_class.find(:all)
    true
  end

  def edit_template(_class, _params)
    @db_view = _class.find_by_id(params[:id]) || _class.new
    if request.post?
      attr=@db_view.attributes
p attr
      _params.each do |key, val|
        attr[key]=val
      end
      @db_view.attributes=attr
      return(true) if @db_view.save
    end
    false
  end 

  def delete_template(_class)
    @db_view = _class.find_by_id(params[:id])
    return(true) if @db_view.nil?
    if request.post?
      @db_view.destroy 
      return(true)
    end
    false
  end

 public

  def view_ra_server
    render(:template=>"ca/view_ra_servers") if view_template(RaServer)
  end

  def edit_ra_server
    redirect_to(:action=>"view_ra_server", :id=>@db_view.id) and return if edit_template(RaServer, params[:db_view])
    ca=CaDomain.find_by_name("Rails PKI Webserver CA")
    @ca_items=ca.ca_items || []
  end
 
  def delete_ra_server
      redirect_to(:action=>"view_ra_server", :id=>nil) if delete_template(RaServer)
  end
    
  def view_auth_method
    render(:template=>"ca/view_auth_methods") if view_template(AuthMethod)
  end
   
  def edit_auth_method
    if !params[:db_view].nil? and params[:db_view]["type"].class==String
      params[:db_view]["meth"]={}
      params[:db_view]["meth"][:type]=params[:db_view]["type"]
      params[:db_view].delete("type")
      s=params[:db_view]["check"].gsub(/\r/,'')
      a=s.split(/\n/)
      params[:db_view]["meth"][:check]={}
      a.each do |line|
        if line=~/^([a-z_]+): (.+)$/
          params[:db_view]["meth"][:check][$1]=$2
        end
      end
      params[:db_view].delete("check")
    end
    redirect_to(:action=>"view_auth_method", :id=>@db_view.id) and return if edit_template(AuthMethod, params[:db_view])
  end
 
  def delete_auth_method
      redirect_to(:action=>"view_auth_method", :id=>nil) if delete_template(AuthMethod)
  end

  def view_user
    render(:template=>"ca/view_users") if view_template(User)
  end
   
  def edit_user
    if !params[:db_view].nil? and params[:db_view][:roles].class==Array
      roles=[]
      params[:db_view][:roles].each do |role|
        roles<<Role.find_by_id(role)
      end
      params[:db_view][:roles]=roles
    end
    @roles=Role.find(:all)
    redirect_to(:action=>"view_user", :id=>@db_view.id) and return if edit_template(User, params[:db_view])
  end
 
  def delete_user
      redirect_to(:action=>"view_user", :id=>nil) if delete_template(User)
  end

  def view_role
    render(:template=>"ca/view_roles") if view_template(Role)
  end
   
  def edit_role
    if !params[:db_view].nil? and params[:db_view][:auth_methods].class==Array
      ams=[]
      params[:db_view][:auth_methods].each do |am|
        ams<<AuthMethod.find_by_id(am)
      end
      params[:db_view][:auth_methods]=ams
    end
    redirect_to(:action=>"view_role", :id=>@db_view.id) and return if edit_template(Role, params[:db_view])
    @ca_domains=CaDomain.find(:all)
    @ra_servers=RaServer.find(:all)
    @auth_methods=AuthMethod.find(:all)
  end
 
  def delete_role
      redirect_to(:action=>"view_role", :id=>nil) if delete_template(Role)
  end
    
  def view_ca_domain
    render(:template=>"ca/view_ca_domains") if view_template(CaDomain)
  end

  def edit_ca_domain
    if request.post? and (params[:db_view]["yaml"].class==StringIO or params[:db_view]["yaml"].class==Tempfile)
      yaml_a=params[:db_view]["yaml"].to_a
      params[:db_view]["yaml"]=yaml_a.to_s
    end
    redirect_to(:action=>"view_ca_domain", :id=>@db_view.id) and return if edit_template(CaDomain, params[:db_view])
    if @db_view.dn.nil?
      @ca_domains=CaDomain.find(:all)
      render(:template=>"ca/add_ca_domain")
    end
  end

  def delete_ca_domain
      redirect_to(:action=>"view_ca_domain", :id=>nil) if delete_template(CaDomain)
  end

  def index
  end

  def sync
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
      o=ActionWebService::Client::Soap.new(BackendApi, "https://#{server}/pki/backend/api")

      print "Checking Class CaDomain:\n"
      update=[]
      soap["CaDomain"].each do |did,count|
        attr=CaDomain.find_by_id(did).attributes
        attr["privkey_pem"]="-none-"
        update<<attr.to_yaml
      end
      print " - Update CaDomain...\n"
      begin
        o.update_entries("CaDomain", update) if update.size>0
      rescue
        print "Exception\n"
      end

      links_a=[]
      links_u=[]
      [User, AuthMethod, Role].each do |type_c|
        print "Checking Class #{type_c.name}:\n"
        begin
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
        rescue
          print "Exception\n"
        end
      end
      0.upto(links_u.size-1) do |id|
        next if links_u[id].nil? or links_a[id].nil?
        begin
          o.role_links(id, links_u[id]||[], links_a[id]||[])
        rescue
          print "Exception\n"
        end
      end
    end
  end

end
