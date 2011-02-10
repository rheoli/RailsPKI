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

require 'openssl'

class RaItem < ActiveRecord::Base
  acts_as_state_machine :initial => :request
  
  belongs_to :ca_domain
  has_one    :ra_revoke
  belongs_to :supersede_item, :class_name=>"RaItem", :foreign_key=>"supersede_item_id"
  has_one    :superseded_by, :class_name=>"RaItem", :foreign_key=>"supersede_item_id"
  serialize :dn

  validates_presence_of :csr, :ca_domain_id

  state :request
  state :ready_to_sign
  state :sign_approved
  state :in_signing_process
  state :signed

  event :ready_to_sign do
    transitions :to => :ready_to_sign,    :from => :request
  end

  event :approved do
    transitions :to => :sign_approved,    :from => :ready_to_sign
  end

  event :in_signing_process do
    transitions :to => :in_signing_process,    :from => :sign_approved
  end

  event :signed do
    transitions :to => :signed,           :from => :in_signing_process
  end

  def self.update_yaml_ra_item(_ca_item)
    ca_item=YAML.load(_ca_item)
    ra_item=RaItem.find(ca_item[:id])
    return(nil) if ra_item==nil
    ra_item.dn        =ca_item[:dn]
    ra_item.crt_serial=ca_item[:crt_serial]
    ra_item.crt_begin =ca_item[:crt_begin]
    ra_item.crt_end   =ca_item[:crt_end]
    ra_item.crt_pem   =ca_item[:crt_pem]
    return(nil) if !ra_item.save
    ra_item.signed!
    return(ra_item)
  end

  def self.update_ra_item(_ca_item)
    return(nil) if _ca_item.class!=CaItem
    ra_item=RaItem.find(_ca_item.ra_item_id)
    return(nil) if ra_item==nil
    ra_item.dn        =_ca_item.dn
    ra_item.crt_serial=_ca_item.crt_serial
    ra_item.crt_begin =_ca_item.crt_begin
    ra_item.crt_end   =_ca_item.crt_end
    ra_item.crt_pem   =_ca_item.crt_pem
    return(nil) if !ra_item.save
    ra_item.signed!
    return(ra_item)
  end

  def approve_for_sign(_user_id, _duration=365)
    self.approved!
    self.signer_user_id=_user_id
    self.duration=_duration
    self.save
  end

  def method_missing(symbol, *params)
    if(symbol.to_s =~ /^subject_([A-Za-z]+)$/)
      return('') if self.dn.nil?
      return(self.dn[$1])
    end
    super
  end

 protected
  def validate
    if csr != "" and self.state.nil? then
      check_csr=nil
      spki=nil
      begin
        check_csr=OpenSSL::X509::Request.new(csr)
      rescue
        check_csr=nil
      end
      if check_csr==nil
        spki_csr=csr
        spki_csr.gsub!(/\n/, '')
        spki_csr.gsub!(/\r/, '')
        begin
          spki=OpenSSL::Netscape::SPKI.new(spki_csr)
        rescue
          spki=nil
        end
        if spki==nil
          errors.add("csr", "no X.509 CSR format")
          return
        end
      else
        if !check_csr.verify(check_csr.public_key) then
          errors.add("csr", "can't verify signature")
          return
        end
      end
      ca_domain=CaDomain.find(ca_domain_id) if ca_domain_id!=nil
      if ca_domain==nil
        errors.add("ca_domain_id", "CA not found")
        return
      end
      self.dn={}
      req_dn={}
      if check_csr!=nil
        check_csr.subject.to_a.each do |s|
          req_dn[s[0]]=s[1] if s[1]!="-dummy-"
        end
      end  
      ca_domain.dn_sort_for_sign.each do |c|
        self.dn[c]=req_dn[c]
        if ca_domain.dn_policy["dn_info"][c][0][0]=="match"
          self.dn[c]=ca_domain.dn[c]
        end
      end
    end
  end
  
end
