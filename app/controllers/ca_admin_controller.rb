#--
# Copyright (c) 2006 Stephan Toggweiler
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

class CaAdminController < ApplicationController

  layout "ca"

  before_filter :authorize

  def list_ra_roles
    @roles=RaRole.find_all
  end

  def add_ra_role
  end
  
  def edit_ra_role
    if request.get?
      @ca_defs=CaDefinition.new
      @ca_defs_all=CaDefinition.find_all
    else
      @ca_defs = CaDefinition.new(params[:ca_defs])
      @ca_defs.ca_create(params[:ca_defs])
      if @ca_defs.save
        #flash[:notice] = 'Product was successfully created.'
        redirect_to :action => 'viewca_item', :id => @ca_defs.id
      end
    end
  end


  def index
  end

end
