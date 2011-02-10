require 'net/ldap'

class AuthController < ApplicationController
  layout "auth"
  
  before_filter :authorize, :except => :login

  def index
    redirect_to :action => 'login'
  end
  
  def login
    reset_session
    session[:user]=nil
    
    client_cert=request.env["SSL_CLIENT_CERT"]
    client_cert=request.env["HTTP_SSL_CLIENT_CERT"] if client_cert.nil?

    if !client_cert.nil? and client_cert!=""
      client_cert.gsub!(' CERTIFICATE', '_CERTIFICATE')
      client_cert.gsub!(' ', "\n")
      client_cert.gsub!('_CERTIFICATE', ' CERTIFICATE')
      p client_cert
      cert=OpenSSL::X509::Certificate.new(client_cert)
      session[:cert_issuer]=cert.issuer.to_s
      session[:cert_subject]=cert.subject.to_s
      cert.subject.to_a.each do |val|
        session[:user]=val[1] if val[0]=="UID"
        session[:user_cn]=val[1] if val[0]=="CN"
        session[:user_email]=val[1] if val[0]=="emailAddress"
      end
      session[:auth_method]="client_cert"
    elsif request.post? and session[:user].nil?
      begin
        AuthMethod.find(:all).each do |auth|
          next if auth.meth[:type]!="ldap"
          server="localhost"
          port=389
          server=auth.meth[:check]["server"] if auth.meth[:check]["server"]!=""
          port=auth.meth[:check]["port"].to_i if auth.meth[:check]["port"]!=""
          base_dn=auth.meth[:check]["base_dn"]
          LDAP::Conn.new(server, port).bind("uid=#{params[:user][:username]},#{base_dn}", params[:user][:password]) do |conn|
            res=conn.search2(base_dn, LDAP::LDAP_SCOPE_SUBTREE, "(&(objectClass=inetOrgPerson)(uid=#{params[:user][:username]}))", ['mail'] )
            session[:user]=params[:user][:username]
            session[:user_mail]=res[0]["mail"]
            session[:auth_method]="ldap"
            break
          end
        end
      rescue
p "Bad LDAP"
      end

      if session[:user].nil?
        user = User.authenticate( params[:user][:username], params[:user][:password] )
        if user.nil?
          flash.now[:notice] = 'Username or password is incorrect'
        else
          session[:user] = user.username
          session[:auth_method]="user_password"
        end
      end
    end
    if !session[:user].nil?
      session[:role] = nil
      redirect_to :action => 'change_role'
      return
    end
  end
  
  def change_role
    @roles=[]
    return(redirect_to_access_denied('Access denied. (Unknown user)')) if current_user.nil?
    current_user.roles.each do |role|
      role.auth_methods.each do |am|
        next if am.meth[:type]!=session[:auth_method]
        if am.meth[:type]=="client_cert" and session[:cert_issuer]==am.meth[:check][:issuer_dn]
          @roles<<role
        end
        if am.meth[:type]=="user_password"
          @roles<<role
        end
        if am.meth[:type]=="ldap"
          @roles<<role
        end
      end
    end
    return(redirect_to_access_denied('Access denied. (No role found)')) if @roles.size==0
    if @roles.size==1
      session[:role]=@roles[0].id
    end
    if request.post? or @roles.size==1
      session[:role] = params[:role].to_i if params[:role].to_i>0
      rdr_controller='ra'
      rdr_controller='ca' if current_role.name==Role::ROLE_CA_ADMIN
      redirect_to :controller => rdr_controller, :action => 'index'
    end
  end
  
  def access_denied
  end
  
  def logout
    reset_session
    session[:user] = nil
  end

end
