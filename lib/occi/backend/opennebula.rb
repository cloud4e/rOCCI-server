require 'rubygems'
require 'uuidtools'
require 'oca'
require 'occi/model'

require 'occi/backend/opennebula/auth/server_cipher_auth'

require 'occi/backend/manager'

# OpenNebula backend based mixins
#require 'occi/extensions/one/Image'
#require 'occi/extensions/one/Network'
#require 'occi/extensions/one/VirtualMachine'
#require 'occi/extensions/one/VNC'

#require 'occi/extensions/Reservation'

require 'occi/log'
require 'pstore'
require 'openssl'

include OpenNebula

module OCCI
  module Backend
    class OpenNebula < OCCI::Core::Resource

      # Default interval for timestamps. Tokens will be generated using the same
      # timestamp for this interval of time.
      # THIS VALUE CANNOT BE LOWER THAN EXPIRE_MARGIN
      EXPIRE_DELTA  = 1800

      # Tokens will be generated if time > EXPIRE_TIME - EXPIRE_MARGIN
      EXPIRE_MARGIN = 300

      attr_reader :model
      attr_accessor :amqp_worker

      def self.kind_definition
        kind = OCCI::Core::Kind.new('http://rocci.info/server/backend#', 'opennebula')

        kind.related = %w{http://rocci.org/serer#backend}
        kind.title   = "rOCCI OpenNebula backend"

        kind.attributes.info!.rocci!.backend!.opennebula!.admin!.Default     = 'oneadmin'
        kind.attributes.info!.rocci!.backend!.opennebula!.admin!.Pattern     = '[a-zA-Z0-9_]*'
        kind.attributes.info!.rocci!.backend!.opennebula!.admin!.Description = 'Username of OpenNebula admin user'

        kind.attributes.info!.rocci!.backend!.opennebula!.password!.Description = 'Password for OpenNebula admin user'
        kind.attributes.info!.rocci!.backend!.opennebula!.password!.Required    = true

        kind.attributes.info!.rocci!.backend!.opennebula!.endpoint!.Default = 'http://localhost:2633/RPC2'

        kind.attributes.info!.rocci!.backend!.opennebula!.scheme!.Default = 'http://my.occi.service/'

        kind
      end

      def initialize(kind='http://rocci.org/server#backend', mixins=nil, attributes=nil, links=nil)
        scheme = attributes.info!.rocci!.backend!.opennebula!.scheme if attributes
        scheme ||= self.class.kind_definition.attributes.info.rocci.backend.opennebula.scheme.Default
        scheme.chomp('/')
        @model = OCCI::Model.new
        @model.register_core
        @model.register_infrastructure
        @model.register_files('etc/backend/opennebula/model/infrastructure/amqp', scheme)
        @model.register_files('etc/backend/opennebula/model', scheme)
        @model.register_files('etc/backend/opennebula/templates', scheme)
        OCCI::Backend::Manager.register_backend(OCCI::Backend::OpenNebula, OCCI::Backend::OpenNebula::OPERATIONS)

        admin    = attributes.info.rocci.backend.opennebula.admin
        password = attributes.info.rocci.backend.opennebula.password

        @server_auth           = OpenNebula::Auth::ServerCipherAuth.new(admin, password)
        @token_expiration_time = Time.now.to_i + 1800
        @endpoint              = attributes.info.rocci.backend.opennebula.endpoint
        @lock                  = Mutex.new

        # TODO: create mixins from existing templates

        # initialize OpenNebula connection
        OCCI::Log.debug("### Initializing connection with OpenNebula")

        # TODO: check for error!
        #       @one_client = Client.new(OCCI::Server.config['one_user'] + ':' + OCCI::Server.config['one_password'], OCCI::Server.config['one_xmlrpc'])
        # @one_client = OpenNebula::Client.new(admin + ':' + password, endpoint)

        puts "OpenNebula successful initialized"
        super(kind, mixins, attributes, links)
      end

      def authorized?(username, password)
        return if username.blank? || password.blank?
        (get_password(username, 'core|public') == Digest::SHA1.hexdigest(password))
      end

      # Gets the password associated with a username
      # username:: _String_ the username
      # driver:: _String_ list of valid drivers for the user, | separated
      # [return] _Hash_ with the username
      def get_password(username, driver=nil)
        user_pool = OpenNebula::UserPool.new(client)
        rc        = user_pool.info
        raise rc.message if check_rc(rc)

        xpath = "USER[NAME=#{username.encode(:xml => :attr)}"
        if driver
          xpath << " and (AUTH_DRIVER=\""
          xpath << driver.split('|').join("\" or AUTH_DRIVER=\"") << '")'
        end
        xpath << "]/PASSWORD"

        user_pool[xpath]
      end

      # Gets the username associated with a cert_subject
      # cert_subject:: _String_ DN from user's certificate
      # [return] _Hash_ with the username
      def get_username(cert_subject)
        user_pool = OpenNebula::UserPool.new(client)
        rc        = user_pool.info
        raise rc.message if check_rc(rc)

        password = password.to_s.delete("\s")

        xpath = "USER[PASSWORD=\"#{password}\"]/NAME"
        username = user_pool[xpath]

        if username.nil?
          user_pool.each do |x509_user|
            x509_user["PASSWORD"].split('|').each do |x509_user_dn|
              if x509_user_dn == password
                username = x509_user["NAME"]
                break
              end
            end if x509_user["AUTH_DRIVER"] == "x509"

            break unless username.nil?
          end
        end

        username
      end

      # Generate a new OpenNebula client for the target User, if the username
      # is nil the Client is generated for the server_admin
      # ussername:: _String_ Name of the User
      # [return] _Client_
      def client(username=nil)
        expiration_time = @lock.synchronize {
          time_now = Time.now.to_i

          if time_now > @token_expiration_time - EXPIRE_MARGIN
            @token_expiration_time = time_now + EXPIRE_DELTA
          end

          @token_expiration_time
        }

        @pstore = PStore.new(username.split(":").first)
        @pstore.transaction do
          @pstore['links']   ||= []
          @pstore['mixins']  ||= []
          @pstore['actions'] ||= []
        end

        #register saved mixins and actions
        @pstore.transaction(read_only=true) do
          actions = @pstore['actions']

          actions.each do |action|
            @model.register(action)
          end

         

          mixins = @pstore['mixins']


          mixins.each do |mixin|
            @model.register(mixin)
          end
        end


        #token = @server_auth.login_token(expiration_time, username)
        token=username

        OpenNebula::Client.new(token, @endpoint)
      end

      # The ACL level to be used when querying resource in OpenNebula:
      # - INFO_ALL returns all resources and works only when running under the oneadmin account
      # - INFO_GROUP returns the resources of the account + his group (= default)
      # - INFO_MINE returns only the resources of the account
      INFO_ACL = OpenNebula::Pool::INFO_GROUP

      # OpenNebula backend
      require 'occi/backend/opennebula/compute'
      require 'occi/backend/opennebula/network'
      require 'occi/backend/opennebula/storage'

      include OCCI::Backend::OpenNebula::Compute
      include OCCI::Backend::OpenNebula::Network
      include OCCI::Backend::OpenNebula::Storage


      # Operation mappings

      OPERATIONS = { }

      OPERATIONS["http://schemas.ogf.org/occi/infrastructure#compute"] = {

          # Generic resource operations
          :deploy       => :compute_deploy,
          :update_state => :compute_update_state,
          :delete       => :compute_delete,

          # Compute specific resource operations
          :start        => :compute_start,
          :stop         => :compute_stop,
          :restart      => :compute_restart,
          :suspend      => :compute_suspend,
          :chgrp        => :compute_chgrp
      }

      OPERATIONS["http://schemas.ogf.org/occi/infrastructure#amqplink"] = {
          :link   => :amqplink_link,
          :delete => :amqplink_delete,
          :amqp_call => :amqplink_call
      }     

      OPERATIONS["http://schemas.ogf.org/occi/infrastructure#network"] = {

          # Generic resource operations
          :deploy       => :network_deploy,
          :update_state => :network_update_state,
          :delete       => :network_delete,

          # Network specific resource operations
          :up           => :network_up,
          :down         => :network_down
      }

      OPERATIONS["http://schemas.ogf.org/occi/infrastructure#storage"] = {

          # Generic resource operations
          :deploy       => :storage_deploy,
          :update_state => :storage_update_state,
          :delete       => :storage_delete,

          # Network specific resource operations
          :online       => :storage_online,
          :offline      => :storage_offline,
          :backup       => :storage_backup,
          :snapshot     => :storage_snapshot,
          :resize       => :storage_resize
      }

      # ---------------------------------------------------------------------------------------------------------------------
      #        private
      # ---------------------------------------------------------------------------------------------------------------------

      # ---------------------------------------------------------------------------------------------------------------------
      def check_rc(rc)
        if rc.class == Error
          raise OCCI::BackendError, "Error message from OpenNebula: #{rc.to_str}"
          # TODO: return failed!
        end
      end

      # ---------------------------------------------------------------------------------------------------------------------
      # Generate a new occi id for resources created directly in OpenNebula using a seed id and the kind identifier
      def generate_occi_id(kind, seed_id)
        # Use strings as kind ids
        kind = kind.type_identifier if kind.kind_of?(OCCI::Core::Kind)
        return UUIDTools::UUID.sha1_create(UUIDTools::UUID_DNS_NAMESPACE, "#{kind}:#{seed_id}").to_s
      end

      # ---------------------------------------------------------------------------------------------------------------------
      public
      # ---------------------------------------------------------------------------------------------------------------------


      # ---------------------------------------------------------------------------------------------------------------------
      def register_existing_resources(client)
        # get all compute objects
        resource_template_register(client)
        os_template_register(client)
        compute_register_all_instances(client)

        entities = []

        @pstore.transaction(read_only=true) do
          entities = @pstore['links']
        end

        entities.each do |entity|          
          #Link zu seiner Resource hinzufügen
          add_actions_from_link(entity)
          if add_link_to_resource(entity)
            kind = @model.get_by_id(entity.kind)
            kind.entities << entity
          end
          if kind
             OCCI::Log.debug("#### Number of entities in kind #{kind.type_identifier}: #{kind.entities.size}")
          end
        end
        

        #network_register_all_instances(client)
        #storage_register_all_instances(client)
      end

      #------------------------------------------------------------------------------------------------
      #Tries to update all known amqp links
      def update_all_links(client)
         OCCI::Log.debug("Update all AMQP links")
         links = []
         @pstore.transaction(read_only=true) do
           links = @pstore['links']
         end
         update_links(client,links)
      end

      #------------------------------------------------------------------------------------------------
      #Tries to update all amqp links of the given array of compute resources
      def update_links_of_compute_resources(client,computes)
        computes.each do |compute|
           #TEST
           #backend_vm_pool = OpenNebula::VirtualMachinePool.new(client)
           #backend_vm_pool.info_all
           #backend_vm_pool.each do |backend_vm|
           #  if backend_vm['TEMPLATE/OCCI_ID']==compute.id
           #    tpl = backend_vm['TEMPLATE']
           #    puts tpl.class.name
           #    puts tpl.inspect
           #    backend_vm.add_element('TEMPLATE','NEW_ITEM' => 'TEST')
           #  end
           #end
           #TEST ENDE
           links=[]
           @pstore.transaction(read_only=true) do
              links = @pstore['links']
           end
           links_of_resource=links.select {|link| link.source.rpartition('/').last == compute.id}
           update_links(client,links_of_resource)            
        end 
      end

      #------------------------------------------------------------------------------------------------
      #Tries to update all amqp links given in the array links
      def update_links(client,links)        
        connection = AMQP.connection
        links_waiting_for_reply=[]
        links.each do |entity|         
          if entity.attributes.has_key?("occi") && entity.attributes.occi.has_key?("amqplink") &&
          entity.attributes.occi.amqplink.has_key?("queue") && entity.attributes.occi.amqplink.queue &&
          entity.attributes.occi.amqplink.queue != ""
             #If service_adapter is listening we request an update of the link attributes.
             #In order to test if adapter is listening we test if queue exists. 
             queue_name = entity.attributes.occi.amqplink.queue
             channel  = AMQP::Channel.new(connection)
             queue_tested=false
             queue_exists=false            
             channel.on_error do
                queue_tested=true
                queue_exists=true 
             end
          
             queue=channel.queue(queue_name)          
             #the block is only executed if queue did not already exist, otherwise an error occurs 
             queue.status do |num_messages, num_consumers|            
                OCCI::Log.debug("Queue "+queue_name+" does not exist")
                queue.delete
                queue_tested=true
             end

             #wait until we know if queue exists 
             while !queue_tested
             end

             if queue_exists
                channel2  = AMQP::Channel.new(connection)
                OCCI::Log.debug("Queue "+queue_name+" exists")
                reply_queue_name=queue_name+"-reply"
                options = {
                   :routing_key  => queue_name,
                   :reply_to => reply_queue_name
                }
                message = "update_link"
                reply_queue = channel2.queue(reply_queue_name, :exclusive => true, :auto_delete => true)

   
                reply_queue.subscribe do |header, payload|
                   begin
                      hash = Hashie::Mash.new(JSON.parse(payload))
                      link_new=OCCI::Core::Link.new(hash.kind, hash.mixins, hash.attributes, hash.actions, hash.rel, hash.target, hash.source)
                      link_new.check @model
                      OCCI::Log.debug("Got updated link")
                      reply_queue.delete
                
                      if !(entity.as_json.eql?(link_new.as_json))
                         OCCI::Log.debug("Link changed to "+link_new.inspect)
                         store_link link_new 
                         #delete old link from resource... 
                         del_link_from_resource(entity)
                         #and add the new one                         
                         add_actions_from_link(link_new)
                         if add_link_to_resource(link_new)
                            kind = @model.get_by_id(link_new.kind)
                            kind.entities << link_new
                         end
                         if kind
                            OCCI::Log.debug("#### Number of entities in kind #{kind.type_identifier}: #{kind.entities.size}")
                         end
                      else
                         OCCI::Log.debug("Link not changed")
                      end
                      links_waiting_for_reply.delete  entity
                   rescue => e
                      puts e.backtrace
                   end
                end

                @amqp_worker.request(message, options)
                links_waiting_for_reply << entity
          
             else
                #Link zu seiner Resource hinzufügen
                #add_actions_from_link(entity)
                #if add_link_to_resource(entity)
                #   kind = @model.get_by_id(entity.kind)
                #   kind.entities << entity
                #end
                #if kind
                #   OCCI::Log.debug("#### Number of entities in kind #{kind.type_identifier}: #{kind.entities.size}")
                #end
             end
          end #if
        end #each
        #timeout in seconds for waiting for replies
        timeout=3
        while !(links_waiting_for_reply.empty?) && timeout>0
           sleep(0.1)
           timeout=timeout-1
        end 
        if !(links_waiting_for_reply.empty?)
            OCCI::Log.warn("Failed to update one or more links - timeout exceeded")
            #links_waiting_for_reply.each do |entity|
            #   add_actions_from_link(entity)
            #   if add_link_to_resource(entity)
            #      kind = @model.get_by_id(entity.kind)
            #      kind.entities << entity
            #   end
            #   if kind
            #      OCCI::Log.debug("#### Number of entities in kind #{kind.type_identifier}: #{kind.entities.size}")
            #   end
            #end 
        end
      end

      def add_actions_from_link(link)
        if link.mixins.any?
          #has mixins

          link.mixins.each do |key, value|
            mixin = @model.get_by_id key
            if mixin.actions.any?
              mixin.actions.each do |key2, value2|
                link.actions << key2
              end
            end
            link.actions.uniq!
          end
        end
      end      

      def add_link_to_resource(link)
        source = link.source
        kind = @model.get_by_location(source.rpartition('/').first + '/')
        uuid = source.rpartition('/').last

        resource = (kind.entities.select { |entity| entity.id == uuid } if kind.entity_type == OCCI::Core::Resource).first
        if !resource.nil?
          resource.links << link
          true
        else
          #source does not exist
          amqplink_delete(@pstore, link)
          false
        end
      end

      def del_link_from_resource(link)
        source = link.source
        kind = @model.get_by_location(source.rpartition('/').first + '/')
        uuid = source.rpartition('/').last

        resource = (kind.entities.select { |entity| entity.id == uuid } if kind.entity_type == OCCI::Core::Resource).first
        if !resource.nil?
          resource.links.delete_if{|item| item.id==link.id}
        end
      end
 
      
      # ---------------------------------------------------------------------------------------------------------------------
      def resource_template_register(client)
        # currently not directly supported by OpenNebula
      end

      # ---------------------------------------------------------------------------------------------------------------------
      def os_template_register(client)
        (@model.get.mixins.select { |mixin| mixin.related.select { |rel| rel.end_with? 'os_tpl' }.any? }).each do |tpl|
            @model.unregister(tpl)
        end
        backend_object_pool=TemplatePool.new(client)
        backend_object_pool.info_all
        backend_object_pool.each do |backend_object|
          related = %w|http://schemas.ogf.org/occi/infrastructure#os_tpl|
          term    = backend_object['NAME'].downcase.chomp.gsub(/\W/, '_')
          # TODO: implement correct schema for service provider
          scheme  = self.attributes.info.rocci.backend.opennebula.scheme + "/occi/infrastructure/os_tpl#"
          title   = backend_object['NAME']
          mixin   = OCCI::Core::Mixin.new(scheme, term, title, nil, related)
          @model.register(mixin)
        end
      end

      def store_mixin(mixin, delete = false)
        @pstore.transaction do
          @pstore['mixins'].delete_if { |res| res.type_identifier == mixin.type_identifier }
          @pstore['mixins'] << mixin unless delete
        end
      end

      def store_link(link, delete = false)
        OCCI::Log.debug("### OpenNebula: Deploying link with id #{link.id}")
        @pstore.transaction do
          @pstore['links'].delete_if { |res| res.id == link.id }
          @pstore['links'] << link unless delete
        end
      end

      def store_action(action, delete = false)
        @pstore.transaction do
          @pstore['actions'].delete_if { |res| res.type_identifier == action.type_identifier }
          @pstore['actions'] << action unless delete
        end
      end


      def register_mixin(mixin)

        #convert actions from occi 3.0.x to occi 2.5.x
        actions = mixin.actions
        mixin.actions = []
        actions.each do |action|
          mixin.actions << (action.scheme + action.term)
        end

        store_mixin mixin
        @model.register(mixin)
      end      

      def unregister_mixin(mixin)
        #search if mixin is in use
        found_mixin = false

        @model.get.kinds.each do |kind|
          break if found_mixin
          kind.entities.each do |entity|
            if entity.mixins.select{|smixin| smixin == mixin.type_identifier}.any?
              found_mixin = true
              break
            end
          end
        end

        unless found_mixin
          #unregister in Model
          @model.categories.delete mixin.type_identifier
          @model.locations.delete mixin.location
          store_mixin mixin, true

          mixin.actions.each do |action|
            #unregister actions
            action.type_identifier = (action.scheme + action.term)
            @model.categories.delete action.type_identifier
            #delete from pstore
            store_action action, true
          end
        end
      end

      def register_action(action)
        store_action action
        @model.register(action)
      end 

      # ---------------------------------------------------------------------------------------------------------------------
      def send_to_amqp(amqp_queue, resource, action, parameters)
        OCCI::Log.debug("Delegating action to amqp_queue: [#{amqp_queue}]")

        if @amqp_worker
          path = resource.location + "?action=" + parameters[:action]

          #alles ausser action und method
          parameters.each do |key, value|
            unless key.to_s == "action" || key.to_s == "method"
              path += "&" + key.to_s + "=" + value.to_s
            end
          end

          options = {
              :routing_key  => amqp_queue,
              :content_type => "application/occi+json",
              :type         => "post",
              :headers => {
                  :path_info => path
              }
          }
          collection   = OCCI::Collection.new
          collection.actions << action



          message = collection.to_json
          @amqp_worker.request(message, options)
          test = test
        end
      end

      def amqplink_link(client, amqplink, update=false)
        if !update
          amqplink.id = UUIDTools::UUID.timestamp_create.to_s
        end
        store_link amqplink
      end

      def amqplink_delete(client, amqplink)
        #link aus resource lösen und dann löschen
        store_link amqplink, true
      end

      def amqplink_call(client, amqplink, parameters=nil)
        #TODO Link muss angepasst werden
        amqp_target = amqplink.target
        queue       = amqplink.attributes.occi.amqplink.queue
        action      = parameters["action"]
        params      = parameters["parameters"]
        params.delete(:action)
        params.delete(:method)

        raise "No Amqp Worker is set" unless @amqp_worker

        path = amqplink.location + "?action=" + action.term


        params.each do |key, value|
          path += "&" + key.to_s + "=" + value.to_s
        end

        options = {
            :routing_key  => queue,
            :content_type => "application/occi+json",
            :type         => "post",
            :headers => {
                :path_info => path
            }
        }
        collection = OCCI::Collection.new
        collection.actions << action
        message = collection.to_json

        @amqp_worker.request(message, options)
        #TODO vergiss nicht das occi 2.5.16 gem mit den änderungen an dem parser -> link rel actions source target

      end
 
      def next_message_id
        @message_id  = 0 if @message_id.nil?
        @message_id += 1
        @message_id.to_s;
      end

      def handle_service(client,compute)
         OCCI::Log.debug("Checking VM #{compute.id} for service provider")

         vm_object=nil
         vm_id=-1
         service_provider=nil

         admin_token=attributes.info.rocci.backend.opennebula.admin+":"+attributes.info.rocci.backend.opennebula.password
         admin_client = client(admin_token)

         backend_vm_pool = OpenNebula::VirtualMachinePool.new(admin_client)
         backend_vm_pool.info_all
         backend_vm_pool.each do |backend_vm|
           if backend_vm['TEMPLATE/OCCI_ID']==compute.id || backend_vm['USER_TEMPLATE/OCCI_ID']==compute.id
               #we have to retrieve vm with admin right in order to modify it
               backend_vm_pool_user = OpenNebula::VirtualMachinePool.new(client)
               backend_vm_pool_user.info_all
               user_has_access=false
               backend_vm_pool_user.each do |backend_vm_user|
                   if backend_vm_user.id==backend_vm.id
                       user_has_access=true
                       break
                   end
               end
               if user_has_access
                   vm_object=backend_vm
                   vm_id=backend_vm.id
                   service_provider=backend_vm['TEMPLATE/PROVIDER']
                   break
               end
           end
         end

         if vm_object
           if service_provider
             OCCI::Log.debug("Found service provided by #{service_provider}")
             group = OpenNebula::Group.new(OpenNebula::Group.build_xml(),admin_client);
             group_name="service-"+compute.id
             rc = group.allocate(group_name);
             check_rc(rc)

             user_pool=OpenNebula::UserPool.new(admin_client)
             user_pool.info
             provider_id=-1
             user_pool.each do |user_element|
               if user_element.name==service_provider
                 provider_id=user_element.id
                 break
               end
             end
             if provider_id>=0

               #change group of vm
               rc = vm_object.chown(-1,group.id)
               check_rc(rc)

               acl=OpenNebula::Acl.new(OpenNebula::Acl.build_xml,admin_client)
               check_rc(acl)

               #give provider use rights for vm
               new_acl=OpenNebula::Acl.parse_rule("##{provider_id} VM/##{vm_id} USE")
               rc = acl.allocate(new_acl[0],new_acl[1],new_acl[2])
               check_rc(rc)

               #give provider use rights for the new group
               new_acl=OpenNebula::Acl.parse_rule("##{provider_id} GROUP/##{group.id} USE")
               rc = acl.allocate(new_acl[0],new_acl[1],new_acl[2])
               check_rc(rc)


             end
           else
             OCCI::Log.debug("No service VM")
           end
         else
           OCCI::Log.debug("No running VM with occi id #{compute.id} found")
         end

      end

      def delete_service(client,compute)
          vm_object=nil
          vm_id=-1
          service_provider=nil


          backend_vm_pool = OpenNebula::VirtualMachinePool.new(client)
          backend_vm_pool.info_all
          backend_vm_pool.each do |backend_vm|
            if backend_vm['TEMPLATE/OCCI_ID']==compute.id
                vm_object=backend_vm
                vm_id=backend_vm.id
                service_provider=backend_vm['TEMPLATE/PROVIDER']
                break
            end
          end

          if service_provider
              OCCI::Log.debug("Delete group and ACLs for service provided by #{service_provider}")
              admin_token=attributes.info.rocci.backend.opennebula.admin+":"+attributes.info.rocci.backend.opennebula.password
              admin_client = client(admin_token)

              gid = vm_object.gid
              group = OpenNebula::Group.new(OpenNebula::Group.build_xml(gid),admin_client)
              group.delete

              user_pool=OpenNebula::UserPool.new(admin_client)
              user_pool.info
              provider_id=-1
              user_pool.each do |user_element|
                if user_element.name==service_provider
                  provider_id=user_element.id
                  break
                end
              end
              if provider_id>=0

                acl_pool = OpenNebula::AclPool.new(admin_client)
                acl_pool.info
                acl_to_delete=OpenNebula::Acl.parse_rule("##{provider_id} VM/##{vm_id} USE")

                acl_pool.each do |acl|
                   if(acl_to_delete[0]==acl['USER'] && acl_to_delete[1]==acl['RESOURCE'] && acl_to_delete[2]==acl['RIGHTS']) then
                     rc = acl.delete
                     check_rc(rc)
                     OCCI::Log.debug("Group and ACLs successful deleted")
                   end
                end
              end
           end
      end

      def compute_chgrp(client, compute, parameters)
          vm_object=nil
          backend_vm_pool = OpenNebula::VirtualMachinePool.new(client)
          backend_vm_pool.info_all
          backend_vm_pool.each do |backend_vm|
          if backend_vm['TEMPLATE/OCCI_ID']==compute.id || backend_vm['USER_TEMPLATE/OCCI_ID']==compute.id
              vm_object=backend_vm
              break
           end
         end
         if(vm_object)
             gid=parameters[:gid].to_i
             rc = vm_object.chown(-1,gid)
             check_rc(rc)
         end
      end

    end
  end
end
