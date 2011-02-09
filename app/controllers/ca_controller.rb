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

  before_filter :authorize, :except => :login

# --<Admin>--

  def ca_def_add
    if request.get?
      @ca_defs=CaDefinition.new
      @ca_defs_all=CaDefinition.find_all
    else
      @ca_defs = CaDefinition.new(params[:ca_defs])
      @ca_defs.ca_create(params[:ca_defs])
      if @ca_defs.save
        #flash[:notice] = 'Product was successfully created.'
        redirect_to :action => 'ca_def_list', :id => @ca_defs.id
      end
    end
  end
  
  def ca_def_delete
    if params[:id] != "" then
      @ca_defs=CaDefinition.find(params[:id])
      @ca_defs.destroy
    end
    redirect_to :action => 'ca_def_list', :id => nil
  end

  def ca_def_list
    if params[:id]!=nil
      @ca_defs=CaDefinition.find(params[:id])
      if @ca_defs==nil
        redirect_to :action => 'ca_def_list', :id => nil
        return
      end
      @ca_defs.set_pubkey
      render(:template=>"ca/ca_def_list_item")
    else
      @ca_defs_all=CaDefinition.find_all
    end
  end


# --<RA Sync>--

  def request_get
    @log=[]
    RaServer.find_all.each do |rs|
      if rs.name=="-local-"
        RaItem.find(:all, :conditions=>["state like ?", RaItem::STATE_READY_TO_SIGN]).each do |ri|
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
  
# --<Sign>--

  def sign
    if params[:id]!=nil
      @ca_item=CaItem.find(params[:id])
      if @ca_item==nil
        redirect_to :action => 'sign', :id => nil
        return
      end
      if request.post?
        s_csr=nil
        begin
          s_csr=OpenSSL::X509::Request.new(@ca_item.csr)
        rescue
          s_csr=nil
        end
        if s_csr==nil
          spki_csr=@ca_item.csr
          spki_csr.gsub!(/\n/, '')
          spki_csr.gsub!(/\r/, '')
          begin
            s_csr=OpenSSL::Netscape::SPKI.new(spki_csr)
          rescue
            s_csr=nil
          end
          if s_csr==nil
            redirect_to :action => 'sign', :id => nil
            return
          end
        end  
        s_cert=@ca_item.ca_definition.ca_sign(s_csr, nil, @ca_item.dn)
        @ca_item.crt_pem   =s_cert.to_pem
        @ca_item.crt_serial=s_cert.serial.to_i
        @ca_item.crt_begin =s_cert.not_before
        @ca_item.crt_end   =s_cert.not_after
        @ca_item.state     =CaItem::STATE_SIGNED
        @ca_item.save
        redirect_to :action => 'cert_view', :id => params[:id]
      else
        render(:template=>"ca/sign_item.rhtml")
      end
    else
      @ca_items=CaItem.find(:all, :conditions=>["state like ?", CaItem::STATE_READY_TO_SIGN])
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

  def login
    if request.get?
      session[:user_id] = nil
    else
      has_access=false
      
      has_access=true

      if has_access
        reset_session
        session[:user_id]="user"
        jumpto=session[:login_jumpto] || { :action => "index" }
        session[:login_jumpto] = nil
        redirect_to(jumpto)
      else
        flash[:notice] = "Invalid user/password combination"
      end
    end
  end
  
  def logout
    reset_session
    flash[:notice] = "Logged out"
    redirect_to(:action => "login")
  end

end

#=EOF