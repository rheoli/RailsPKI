class AuthController < ApplicationController
  layout "auth"
  
  before_filter :authorize, :except => :login

  def index
  end
  
  def login
    reset_session
    session[:user]=nil
    
    if !request.env["SSL_CLIENT_CERT"].nil?
      cert=OpenSSL::X509::Certificate.new(request.env["SSL_CLIENT_CERT"])
      session[:cert_issuer]=cert.issuer.to_s
      session[:cert_subject]=cert.subject.to_s
      cert.subject.to_a.each do |val|
        session[:user]=val[1] if val[0]=="UID"
        session[:user_cn]=val[1] if val[0]=="CN"
        session[:user_email]=val[1] if val[0]=="emailAddress"
      end
      session[:auth_method]="client_cert"
    end
    
    if request.post? and session[:user].nil?
      user = User.authenticate( params[:user][:username], params[:user][:password] )
      if user.nil?
        flash.now[:notice] = 'Username or password is incorrect'
      else
        session[:user] = user.id
        session[:auth_method]="user_password"
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
    current_user.roles.each do |role|
      role.auth_methods.each do |am|
        next if am.meth[:type]!=session[:auth_method]
        if am.meth[:type]=="client_cert" and session[:cert_issuer]==am.meth[:check][:issuer_dn]
          @roles<<role
        end
        if am.meth[:type]=="user_password"
          @roles<<role
        end
      end
    end
    redirect_to_access_denied('Access denied. (No role found)') if @roles.size==0
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
