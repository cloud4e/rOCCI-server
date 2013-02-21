require "occi/frontend/amqp/amqp_frontend"
require "occi/frontend/amqp/amqp_request"
require "occi/frontend/amqp/amqp_response"
require "occi/frontend/base/base_frontend"

module OCCI
  module Frontend
    module Amqp
      class AmqpFrontend < OCCI::Frontend::Base::BaseFrontend

        def initialize()
          log("debug", __LINE__, "Initialize AMQPFrontend")
          super
        end

        # @param [OCCI::Frontend::Amqp::AmqpRequest] request
        # @return [String]
        def check_authorization(request)
          if request.env['HTTP_X_AUTH_TOKEN']
            username = @backend.get_username(request.env['HTTP_X_AUTH_TOKEN'], "KEYSTONE")
          else if request.auth["username"]
            return request.auth["username"]
          end

          username ||= 'anonymous'
        end
      end
    end
  end
end
