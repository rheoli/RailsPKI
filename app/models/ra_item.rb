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
  belongs_to :ca_definition
  
  serialize :dn

  validates_presence_of :csr, :ca_definition_id

  STATE_REQUEST      ="request"
  STATE_READY_TO_SIGN="ready_to_sign"
  STATE_IN_SIGNING   ="in_signing_process"
  STATE_SIGNED       ="signed"

  def self.update_ra_item(_ca_item)
    return(nil) if _ca_item.class!=CaItem
    ra_item=RaItem.find(_ca_item.ra_item_id)
    return(nil) if ra_item==nil
    ra_item.dn        =_ca_item.dn
    ra_item.crt_serial=_ca_item.crt_serial
    ra_item.crt_begin =_ca_item.crt_begin
    ra_item.crt_end   =_ca_item.crt_end
    ra_item.crt_pem   =_ca_item.crt_pem
    ra_item.state     =RaItem::STATE_SIGNED
    return(nil) if !ra_item.save
    return(ra_item)
  end

  def method_missing(symbol, *params)
    if(symbol.to_s =~ /^subject_([A-Za-z]+)$/)
      return(self.dn[$1])
    end
    super
  end

 protected
  def validate
    if csr != "" and state==RaItem::STATE_REQUEST then
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
      ca_def=CaDefinition.find(ca_definition_id) if ca_definition_id!=nil
      if ca_def==nil
        errors.add("ca_definition_id", "CA not found")
        return
      end
      self.dn={}
      req_dn={}
      if check_csr!=nil
        check_csr.subject.to_a.each do |s|
          req_dn[s[0]]=s[1] if s[1]!="-dummy-"
        end
      end  
      sort_as=ca_def.dn_policy["sort_as"]
      sort_as=ca_def.dn_policy["sort_as_sign"] if ca_def.dn_policy.has_key?("sort_as_sign")
      sort_as.each do |c|
        self.dn[c]=req_dn[c]
        if ca_def.dn_policy["dn_info"][c][0][0]=="match"
          self.dn[c]=ca_def.dn[c]
        end
      end
    end
  end
end
