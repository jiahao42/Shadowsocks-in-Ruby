#!/usr/bin/ruby

require 'rubygems'
require 'json'
require 'encryptor'
require 'securerandom'

class Utils
  attr_accessor :config
  def initialize
    get_config()
  end

  def get_config()
    config_file = File.new("config.json", "r")
    if config_file
      @config = JSON.parse(config_file.read())
      config_file.close
    else
      puts "Unable to open file!"
    end
  end

  def dump_config()
    puts JSON.pretty_generate(@config)
  end

  def bin2ipv4(bin)
    bin.unpack('H2H2H2H2').join('.')
  end

  def bin2domain(bin, len)
    str = ''
    bin.unpack('H2' * len.to_i).each {|x| str += x.hex.chr}
    return str
  end

  def bin2num(bin)
    return bin.unpack('H*')[0].hex
  end

  def init_cipher(method)
    @cipher = OpenSSL::Cipher.new(method)
    @cipher.encrypt # Required before '#random_key' or '#random_iv' can be called. http://ruby-doc.org/stdlib-2.0.0/libdoc/openssl/rdoc/OpenSSL/Cipher.html#method-i-encrypt
    @secret_key = "Hellooooooooooooooo Woooooooooooorld" # Insures that the key is the correct length respective to the algorithm used.
    @salt = "James"
  end

  def encrypt(data)
    iv = @cipher.random_iv # Insures that the IV is the correct length respective to the algorithm used.
    iv + Encryptor.encrypt(value: data, key: @secret_key, iv: iv, salt: @salt)
  end

  def decrypt(data)
    iv = data[0..11]
    # puts 'iv: ' + iv.unpack('C*').to_s
    Encryptor.decrypt(value: data[12..-1], key: @secret_key, iv: iv, salt: @salt)
  end
end

if __FILE__ == $0
  util = Utils.new
  util.dump_config()
  puts util.bin2ipv4("\x7f\x00\x00\x01")
  puts util.bin2num("\x00\x50")
  puts util.bin2domain("www.yinwang.org", "www.yinwang.org".length)

  util.init_cipher('aes-256-gcm')
  plain_text = "Hello World"
  encrypt_text = util.encrypt(plain_text)
  puts encrypt_text
  puts util.decrypt(encrypt_text)
end