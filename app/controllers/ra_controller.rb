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

   def authorize_ra
     return if !authorize
     redirect_to_access_denied("no role defined") and return if current_role.nil?
     return if current_role.name==Role::ROLE_CA_ADMIN
     redirect_to_access_denied("not enough privileges")
   end

  public

  def server_request
    _certificate_request("server_request")
  end

  def client_request
    _certificate_request("client_request")
  end

  def cert_view
    if params[:id]!=nil then
      @ra_item=RaItem.find(params[:id])
      if @ra_item==nil
        redirect_to :action => 'cert_view', :id => nil
        return
      end
      if @ra_item.crt_pem!=nil
        render(:template=>"ra/cert_view_item_cert.rhtml")
      else
        render(:template=>"ra/cert_view_item_req.rhtml")
      end
    else
      @ra_items=RaItem.find_all
    end
  end

  def cert_revoke
    if params[:id].nil? then
      redirect_to :action => 'cert_view'
      return
    end 
    @ra_item=RaItem.find(params[:id])
    if @ra_item==nil
      redirect_to :action => 'cert_view', :id => nil
      return
    end
    if @ra_item.crt_pem.nil?
      redirect_to :action => 'cert_view', :id => nil
      return
    end
    if request.post?
      r=RaRevoke.new
      r.ra_item_id=@ra_item.id
      r.reason=params[:reason]
      r.save
      redirect_to :action => 'cert_view', :id => nil
      return
    end
  end

  def index
  end

  def genreq
    if params[:ca_id]!=nil and params[:ca_id].to_i>0
      redirect_to :action => 'genreq', :id => params[:ca_id]
      return
    end
    if params[:id]!=nil then
      @ca_domain=CaDomain.find(params[:id])
      if @ca_domain==nil
        redirect_to :action => 'genreq', :id => nil
        return
      end
      if request.post?
        @ra_req = RaReqgen.new
        @ra_req.add_params(params[:id], params[:ra_req])
        if @ra_req.valid?
          @sPKey, @sReqPEM, @sReqText = @ra_req.gen_request
          render(:template=>"ra/genreq_step3.rhtml")
        end
      else
        render(:template=>"ra/genreq_step2.rhtml")
      end
    else
      @ra_req = RaReqgen.new
      @ca_domains=CaDomain.find_all
      render(:template=>"ra/genreq_step1.rhtml")
    end
  end
  
  def sign
    if params[:id]!=nil
      @ra_item=RaItem.find(params[:id])
      if @ra_item==nil
        redirect_to :action => 'sign', :id => nil
        return
      end
      if request.post?
        if @ra_item.approve_for_sign
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
    @ca_domains=CaDomain.find_all
    if request.get?
      @ra_item=RaItem.find(params[:id]) if params[:id]!=nil
      if @ra_item==nil
        #-Step 1 Request
        @ra_item    =RaItem.new
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
        @ra_item        =RaItem.new(params[:ra_item])
        if params[:csr]!=nil
          @ra_item.csr="-----BEGIN CERTIFICATE REQUEST-----\n"
          @ra_item.csr<<params[:csr].gsub(/\\r/, '').gsub(/\\n/,'\n')
          @ra_item.csr<<"-----END CERTIFICATE REQUEST-----\n"
          p @ra_item.csr
        end
        @ra_item.user_id=session[:user]
        if @ra_item.save
          redirect_to :action => _type, :id => @ra_item.id
          return
        end
        render(:template=>"ra/#{_type}_step1.rhtml")
      else
        @ra_item=RaItem.find(params[:id])
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
