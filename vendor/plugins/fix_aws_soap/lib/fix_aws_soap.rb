require 'action_web_service/protocol/soap_protocol'

module ActionWebService # :nodoc:
  module Protocol # :nodoc:
    module Soap # :nodoc:
      class SoapProtocol < AbstractProtocol # :nodoc:
        def encode_request(method_name, params, param_types)
          pack_params = SOAP::Version >= "1.5.5" ? true : false
          param_types.each{ |type| marshaler.register_type(type) } if param_types
          qname = XSD::QName.new(marshaler.namespace, method_name)
          param_def = []
          if param_types
            params = param_types.zip(params).map do |type, param|
              param_def << [ 'in', type.name.to_s, marshaler.lookup_type( type ).mapping ]
              [ type.name.to_s, pack_params ? param : marshaler.ruby_to_soap( param ) ]
            end
          else
            params = []
          end
          request = SOAP::RPC::SOAPMethodRequest.new(qname, param_def)
          if pack_params
            names = request.input_params
            o = Object.new
            idx = 0
            while idx < params.length
              o.instance_variable_set('@' + names[idx], params[idx][1])
              idx += 1
            end
            params = marshaler.ruby_to_soap(o)            
          end
          request.set_param(params)
          envelope = create_soap_envelope(request)
          SOAP::Processor.marshal(envelope)
        end
      end
    end
  end
end
