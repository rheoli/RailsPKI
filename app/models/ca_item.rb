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

class CaItem < ActiveRecord::Base
  belongs_to :ca_definition

  serialize :dn

  validates_presence_of :csr, :ca_definition_id

  STATE_READY_TO_SIGN="ready_to_sign"
  STATE_SIGNED       ="signed"
  STATE_RA_SYNCED    ="ra_synced"

  def self.create_from_ra_item(_ra_server_id, _ra_item)
    return(nil) if _ra_item.class!=RaItem
    ca_item=CaItem.find(:first, :conditions=>["ra_item_id=? and ra_server_id=?", _ra_item.id, _ra_server_id])
    return(nil) if ca_item!=nil
    ca_item=CaItem.new
    ca_item.dn=_ra_item.dn
    ca_item.csr=_ra_item.csr
    ca_item.state=CaItem::STATE_READY_TO_SIGN
    ca_item.ca_definition_id=_ra_item.ca_definition_id
    ca_item.ra_item_id=_ra_item.id
    ca_item.ra_server_id=_ra_server_id
    return(nil) if !ca_item.save
    return(ca_item)
  end
end

