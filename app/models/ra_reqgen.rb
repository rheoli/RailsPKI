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

class RaReqgen
  include Validateable

  BIT_TYPES = [
   ["768 Bit", "768"],
   ["1024 Bit", "1024"],
   ["2048 Bit", "2048"],
  ].freeze

  def self.human_attribute_name(_attr)
    _attr
  end

  def add_params(_ca_id, _params)
    @ca_id=_ca_id
    @params=_params
  end

  def method_missing(symbol, *params)
    symb="#{symbol}".gsub(/:/, '')
    if @valid_params[symb]==true
      @params[symb]
    end
  end

  def validate
    @valid_params={}
    ca_def=CaDefinition.find(@ca_id)
    ca_def.dn_policy["sort_as"].each do |c|
      if ca_def.dn_policy["dn_info"][c][0][0]!="match"
        if @params[c]==nil or @params[c]==""
          errors.add(c, "can't be null")
        else
          @valid_params[c]=true
        end
      end
    end
    if @params["bits"]==nil or @params["bits"]==""
      errors.add(:bits, "has to be bits")
    else
      @valid_params["bits"]=true
    end
    if @params["password"]==nil or @params["password"]==""
      errors.add(:password, "not set")
    else
      @valid_params["password"]=true
    end
    if @params["password"]!=@params["password_confirmation"]
      errors.add(:password, "confirmation wrong")
    else
      @valid_params["password_confirmation"]=true
    end
  end

  def gen_request
    ca_def=CaDefinition.find(@ca_id)
    dn = []
     ca_def.dn_policy["sort_as"].each do |c|
       if ca_def.dn_policy["dn_info"][c][0][0]!="match"
         dn << [c, @params[c], OpenSSL::ASN1::PRINTABLESTRING]
       else
         dn << [c, ca_def.dn[c], OpenSSL::ASN1::PRINTABLESTRING]
       end
     end
    g_dn  =OpenSSL::X509::Name.new(dn)
    g_pkey=OpenSSL::PKey::RSA.new(@params["bits"].to_i)
    g_req =OpenSSL::X509::Request.new
    g_req.version = 0
    g_req.subject = g_dn
    g_req.public_key = g_pkey.public_key
    g_req.sign(g_pkey, OpenSSL::Digest::MD5.new)
    g_pkey_e=g_pkey.to_pem(OpenSSL::Cipher::AES.new("192-CBC"), @params["password"]) 
    return ([g_pkey_e, g_req.to_pem, g_req.to_text])
  end

end
