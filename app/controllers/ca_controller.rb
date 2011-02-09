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

class CaController < ApplicationController
  layout "ca"
  
  before_filter :authorize_ca

 protected
 
  def authorize_ca
    return if !authorize
    redirect_to_access_denied("no role defined") and return if current_role.nil?
    return if current_role.name==Role::ROLE_CA_ADMIN
    redirect_to_access_denied("not enough privileges")
  end
 
 public

# --<Admin>--

  def ca_domain_add
    if request.get?
      @ca_domain=CaDomain.new
      @ca_domains=CaDomain.find_all
    else
      if params[:ca_domain]["yaml"].class!=StringIO and params[:ca_domain]["yaml"].class!=Tempfile
        params[:ca_domain]["yaml"]=nil
      else
        yaml_a=params[:ca_domain]["yaml"].to_a
        params[:ca_domain]["yaml"]=yaml_a.to_s
      end
      @ca_domain = CaDomain.new(params[:ca_domain])
      if @ca_domain.save
        #flash[:notice] = 'Product was successfully created.'
        redirect_to :action => 'ca_domain_list', :id => @ca_domain.id
      end
    end
  end
  
  def ca_domain_delete
    if params[:id] != "" then
      @ca_domain=CaDomain.find(params[:id])
      @ca_domain.destroy
    end
    redirect_to :action => 'ca_domain_list', :id => nil
  end

  def ca_domain_edit
    if params[:id] != "" then
      @ca_domain=CaDomain.find(params[:id])
      return if request.get?
      if params[:ca_domain]["pubkey_pem"]=="" or params[:ca_domain]["privkey_pem"]==""
        @ca_domain.errors.add("pubkey_pem", "can't be null")
        @ca_domain.errors.add("privkey_pem", "can't be null")
        return
      end
      @ca_domain.pubkey_pem=params[:ca_domain]["pubkey_pem"]
      @ca_domain.privkey_pem=params[:ca_domain]["privkey_pem"]
      @ca_domain.save
    end
    redirect_to :action => 'ca_domain_list', :id => nil
  end

  def ca_domain_list
    if params[:id]!=nil
      @ca_domain=CaDomain.find(params[:id])
      if @ca_domain==nil
        redirect_to :action => 'ca_domain_list', :id => nil
        return
      end
      render(:template=>"ca/ca_domain_list_item")
    else
      @ca_domains=CaDomain.find_all
    end
  end


# --<RA Sync>--

  def request_get
    @log=[]
    RaServer.find_all.each do |rs|
      if rs.name=="-local-"
        RaItem.find(:all, :conditions=>["state like ? or state like ?", RaItem::STATE_READY_TO_SIGN, RaItem::STATE_SIGN_APPROVED]).each do |ri|
          if CaItem.create_from_ra_item(rs.id, ri)!=nil
            @log<<"#{rs.name}: #{ri.dn} added"
            ri.state=RaItem::STATE_IN_SIGNING
            ri.save
          end   
        end
      end     
    end
    #o=ActionWebService::Client::Soap.new(BackendApi, "http://localhost:3001/backend/api")
    #p o.find_request_by_id(2)
  end
  
  def request_put
    @log=[]
    RaServer.find_all.each do |rs|
      if rs.name=="-local-"
        CaItem.find(:all, :conditions=>["state like ? and ra_server_id=?", CaItem::STATE_SIGNED, rs.id]).each do |ci|     
          if RaItem.update_ra_item(ci)!=nil
            @log<<"#{rs.name}: #{ci.dn} updated"
            ci.state=CaItem::STATE_RA_SYNCED
            ci.save
          end   
        end
      end     
    end
  end
  
  def sync_db
    @log=[]
    RaServer.find_all.each do |rs|
      next if rs.name=="-local-"
      #-Sync Users
    end
  end

# --<Sign>--

  def sign_approved
    @ca_items=CaItem.find_all_by_state(CaItem::STATE_SIGN_APPROVED)
    if request.post?
      @ca_items.each do |item|
        item.sign_and_save
      end
      redirect_to :action => 'cert_view'
    end
  end

# --<CA>--

  def cert_view
    if params[:id]!=nil then
      @ca_item=CaItem.find(params[:id])
      if @ca_item==nil
        redirect_to :action => 'cert_view', :id => nil
        return
      end
      render(:template=>"ca/cert_view_item.rhtml")
    else
      @ca_items=CaItem.find_all
    end
  end

# --<Others>--

  def index
    
  end



end

#=EOF