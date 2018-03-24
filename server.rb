require 'socket'                 # Get sockets from stdlib
require './utils'

class Server
  def initialize()
    @utils = Utils.new
    @config = @utils.config
    @server_port = @config['server_port']
    @utils.init_cipher(@config['encrypt-method'])
    @server = TCPServer.new(@server_port)
  end
  
  def run() 
    counter = 0
    loop {
      counter += 1
      Thread.start (@server.accept) {|local| 
        Thread.current["id"] = counter;
        thread_run(local);
        puts "Thread [" + Thread.current["id"].to_s + "] is destroyed"
      }
      puts "Thread [" + counter.to_s + "] is created"
    }
  end

  def thread_run(local)
    loop {                           # Servers run forever
      atyp = local.read(1)
      target_addr = '127.0.0.1'
      if atyp == "\x01"
        target_addr = @utils.bin2ipv4(local.read(4))
      elsif atyp == "\x03"
        len = local.read(1).ord
        target_addr = @utils.bin2domain(local.read(len), len)
        puts target_addr
      elsif atyp == "\x04"
        local.read(16) # TODO
      end
      target_port = @utils.bin2num(local.read(2))
      puts target_addr + ":" + target_port.to_s
      remote = TCPSocket.open(target_addr, target_port)
      handle_tcp(local, remote)
      break;
    }
  end

  $blockSize = 1024 * 32
  def handle_tcp(local, remote)
    loop do
      ready = select([local, remote], nil, nil)
      # puts ready[0]
      if ready[0].include? local
          # local -> remote
          data = local.recv($blockSize)
          if data.empty?
              puts "local end closed connection"
              break
          end
          data = @utils.decrypt(data)
          # puts 'data decrypted, length: ' + data.length.to_s
          remote.write(data)
      end
      if ready[0].include? remote
          # remote -> local
          data = remote.recv($blockSize)
          if data.empty?
              puts "remote end closed connection"
              break
          end
          data = @utils.encrypt(data)
          # puts 'data encrypted, length: ' + data.length.to_s
          local.write(data)
      end
    end
  end
end

if __FILE__ == $0
  s = Server.new()
  s.run()
end