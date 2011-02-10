#--
# Copyright (c) 2005-07 Stephan Toggweiler
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

class CaItem < ActiveRecord::Base
  belongs_to :ca_domain
  has_one    :ca_revoke
  belongs_to :supersede_item, :class_name=>"CaItem", :foreign_key=>"supersede_item_id"
  has_one    :superseded_by, :class_name=>"CaItem", :foreign_key=>"supersede_item_id"
  serialize :dn

  validates_presence_of :csr, :ca_domain_id

  acts_as_state_machine :initial => :ready_to_sign

  state :ready_to_sign
  state :signed
  state :ra_synced

  event :signed do
    transitions :to => :signed,           :from => :ready_to_sign
  end

  event :synced do
    transitions :to => :ra_synced,    :from => :signed
  end

  def to_s
    s=""
    self.dn.each do |name, val|
      s<<"/" if s!=""
      s<<"#{name}=#{val}"
    end
    return(s)
  end

  def self.create_from_ra_item(_ra_server_id, _ra_item)
    return(nil) if _ra_item.class!=RaItem and _ra_item.class!=Hash
    if _ra_item.class==RaItem
      _ra_item=_ra_item.attributes
    end
    ca_item=CaItem.find(:first, :conditions=>["ra_item_id=? and ra_server_id=?", _ra_item["id"], _ra_server_id])
    return(nil) if ca_item!=nil
    ca_item=CaItem.new
    ca_item.dn=_ra_item["dn"]
    ca_item.csr=_ra_item["csr"]
    ca_item.user_id=_ra_item["user_id"]
    ca_item.signer_user_id=_ra_item["signer_user_id"]
    ca_item.ca_domain_id=_ra_item["ca_domain_id"]
    ca_item.duration=_ra_item["duration"]
    ca_item.ra_item_id=_ra_item["id"]
    ca_item.ra_server_id=_ra_server_id
    if _ra_item["supersede_item_id"]!=nil and _ra_item["supersede_item_id"]>0
      ss_ca_item=CaItem.find(:first, :conditions=>["ra_item_id=? and ra_server_id=?", _ra_item["supersede_item_id"], _ra_server_id])
      ca_item.supersede_item_id=ss_ca_item.id if ss_ca_item!=nil
    end
    return(nil) if !ca_item.save!
    return(ca_item)
  end

  def export_yaml
    ra_item_data={
      :id         => ra_item_id,
      :dn         => dn,
      :crt_serial => crt_serial,
      :crt_begin  => crt_begin,
      :crt_end    => crt_end,
      :crt_pem    => crt_pem,
    }
    ra_item_data.to_yaml
  end
  
  def sign_and_save
    s_csr=nil
    begin
      s_csr=OpenSSL::X509::Request.new(csr)
    rescue
      s_csr=nil
    end
    if s_csr==nil
      spki_csr=csr
      spki_csr.gsub!(/\n/, '')
      spki_csr.gsub!(/\r/, '')
      begin
        s_csr=OpenSSL::Netscape::SPKI.new(spki_csr)
      rescue
        s_csr=nil
      end
      if s_csr==nil
        raise "Can't identify request certificate"
      end
    end
    duration_sec=self.duration*3600*24
    if self.supersede_item.class==CaItem
      diff_sec=self.supersede_item.crt_end.to_i-Time.now.to_i
      duration_sec=0 if self.supersede_item.ca_revoke.reason=="keyCompromise"
      duration_sec+=diff_sec if diff_sec>0
    end
    s_cert=ca_domain.sign(s_csr, duration_sec, dn)
    self.crt_pem   =s_cert.to_pem
    self.crt_serial=s_cert.serial.to_i
    self.crt_begin =s_cert.not_before
    self.crt_end   =s_cert.not_after
    self.signed!
    return(self.save)
  end
  
end

