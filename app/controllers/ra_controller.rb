#--
# Copyright (c) 2005-06 Stephan Toggweiler
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

class RaController < ApplicationController
  layout "ra"
  
  before_filter :authorize_ra

  protected

   ROLES_METH={
     Role::ROLE_RA_CERT_MGR  => ["index", "cert_view", "server_request", "genreq", "sign", "ca_view", "cert_revoke"],
     Role::ROLE_RA_APPLICANT => ["index", "cert_view", "server_request", "genreq", "ca_view", "cert_revoke"],
   }

   def authorize_ra
     redirect_to_access_denied("not authorized") if !authorize
     redirect_to_access_denied("no role defined") and return if current_role.nil?
     if !ROLES_METH[current_role.name].nil? and current_role.ca_domain.class==CaDomain
       ca_yaml=YAML.load(current_role.ca_domain.yaml)
       if ca_yaml["extensions"]["sign"]["extendedKeyUsage"]=~/emailProtection/ or
           ca_yaml["extensions"]["sign"]["extendedKeyUsage"]=~/clientAuth/
         ROLES_METH[current_role.name]<<"client_request"
       end
       return if ROLES_METH[current_role.name].include?(action_name)
     end
     redirect_to_access_denied("not enough privileges")
   end

  public

  def server_request
    _certificate_request("server_request")
  end

  def client_request
    _certificate_request("client_request")
  end

  def ca_view
    @ca_domain=CaDomain.find_by_id(params[:id])
    if @ca_domain.nil?
      redirect_to :action => 'cert_view', :id => nil
    else
      if !params[:type].nil? and params[:type]=="pem"
        render(:template=>"ra/ca_view_pem.rhtml")
      elsif !params[:type].nil? and params[:type]=="text"
        render(:template=>"ra/ca_view_text.rhtml")
      end
    end
  end

  def cert_view
    if params[:id]!=nil then
      current_ra_item do
        @ra_item=RaItem.find(params[:id])
      end
      if @ra_item==nil
        redirect_to :action => 'cert_view', :id => nil
        return
      end
      if @ra_item.crt_pem!=nil
        if !params[:type].nil? and params[:type]=="pem"
          render(:template=>"ra/cert_view_item_cert_pem.rhtml")
        elsif !params[:type].nil? and params[:type]=="text"
          render(:template=>"ra/cert_view_item_cert_text.rhtml")
        else
          render(:template=>"ra/cert_view_item_cert.rhtml")
        end
        #o=RaMailer.create_check("railspki@rheoli.net", "empf", {})
        #o.set_content_type("text/html")
        #RaMailer.deliver(o)
      else
        render(:template=>"ra/cert_view_item_req.rhtml")
      end
    else
      current_ra_item do
        @ra_items=RaItem.find(:all, :conditions=>["crt_end > datetime('now','localtime')"])
      end
    end
  end

  def cert_revoke
    if params[:id].nil? then
      redirect_to :action => 'cert_view'
      return
    end
    current_ra_item do
      @ra_item=RaItem.find_by_id(params[:id])
    end
    if @ra_item==nil
      redirect_to :action => 'cert_view', :id => nil
      return
    end
    if @ra_item.crt_pem.nil?
      redirect_to :action => 'cert_view', :id => nil
      return
    end
    if @ra_item.ca_domain_id != current_role.ca_domain_id
      redirect_to :action => 'cert_view', :id => nil
      return
    end
    if current_role.name==Role::ROLE_RA_CERT_MGR or (current_role.name==Role::ROLE_RA_APPLICANT and @ra_item.user_id==current_user.di)
      if request.post?
        r=RaRevoke.new
        r.ra_item_id=@ra_item.id
        r.user_id=current_user.id
        r.reason=params[:reason]
        r.save
        redirect_to :action => 'cert_view', :id => nil
        return
      end
    end
  end

  def index
    @methods=ROLES_METH[current_role.name]
  end

  def genreq
    template="ra/genreq_step1.rhtml"
    @ra_req=RaReqgen.new
    @ca_domain=current_role.ca_domain
    if request.post?
      @ra_req.add_params(@ca_domain.id, params[:ra_req])
      if @ra_req.valid?
        @sPKey, @sReqPEM, @sReqText = @ra_req.gen_request
        template="ra/genreq_step2.rhtml"
      end
    end
    render(:template=>template)
  end
  
  def sign
    @ra_item=nil
    if params[:id]!=nil
      current_ra_item do
        @ra_item=RaItem.find_by_id(params[:id])
      end
      if @ra_item==nil
        redirect_to :action => 'sign', :id => nil
        return
      end
      if request.post?
        duration=365
        duration_i=params[:ra_item][:duration].to_i
        if duration_i>1 and duration_i<4
          duration=duration_i*366
        end
        if @ra_item.approve_for_sign(duration)
          redirect_to :action => 'cert_view', :id => params[:id]
        end
      else
        render(:template=>"ra/sign_item.rhtml")
      end
    else
      @ra_items=RaItem.find_all_by_state(RaItem::STATE_READY_TO_SIGN)
    end
  end
  
 private
  
  def _certificate_request(_type)
    @ca_domains=current_role.ca_domain
    if request.get?
      if params[:id]!=nil
        current_ra_item do
          @ra_item=RaItem.find_by_id(params[:id])
        end
      end
      if @ra_item==nil
        #-Step 1 Request
        current_ra_item do
          @ra_item=RaItem.new
        end
        if params[:browser]!="ie" and params[:browser]!="moz"
          render(:template=>"ra/#{_type}_step1.rhtml")
        else
          if params[:browser]=="ie"
            @body_on_load="FindProviders()"
          end
          render(:template=>"ra/#{_type}_step1_#{params[:browser]}.rhtml")
        end
      else
        #-Step 2 Request
        p @ra_item
        render(:template=>"ra/#{_type}_step2.rhtml")
      end
    else
      #-Step 1 Response
      if params[:id]==nil
        current_ra_item do
          @ra_item=RaItem.create(params[:ra_item])
p @ra_item
        end
        #-To Test: @ra_item.ca_domain_id=@ca_domains.id if @ca_domains.class==CaDomain
        if params[:csr]!=nil
          @ra_item.csr="-----BEGIN CERTIFICATE REQUEST-----\n"
          @ra_item.csr<<params[:csr].gsub(/\\r/, '').gsub(/\\n/,'\n')
          @ra_item.csr<<"-----END CERTIFICATE REQUEST-----\n"
          p @ra_item.csr
        end
        #-with_scope: @ra_item.user_id=session[:user]
        if @ra_item.save
          redirect_to :action => _type, :id => @ra_item.id
          return
        end
        render(:template=>"ra/#{_type}_step1.rhtml")
      else
        current_ra_item do
          @ra_item=RaItem.find(params[:id])
        end
        params[:ra_item].each do |k, v|
          if k =~ /^subject_([A-Za-z]+)$/
            @ra_item.dn[$1]=v if @ra_item.dn.has_key?($1) and @ra_item.ca_domain.dn_policy["dn_info"][$1][0][0]!="match"
          end
        end
        @ra_item.state=RaItem::STATE_READY_TO_SIGN
        @ra_item.save
        redirect_to :action => 'cert_view', :id => params[:id]
      end
    end 
  end

end
