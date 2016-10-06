<?php
require '/home/vimrus/other/code/PDOStatement.php';

const CLIENT_LONG_PASSWORD = 1;
const CLIENT_FOUND_ROWS = 1 << 1;
const CLIENT_LONG_FLAG = 1 << 2;
const CLIENT_CONNECT_WITH_DB = 1 << 3;
const CLIENT_NO_SCHEMA = 1 << 4;
const CLIENT_COMPRESS = 1 << 5;
const CLIENT_ODBC = 1 << 6;
const CLIENT_LOCAL_FILES = 1 << 7;
const CLIENT_IGNORE_SPACE = 1 << 8;
const CLIENT_PROTOCOL_41 = 1 << 9;
const CLIENT_INTERACTIVE = 1 << 10;
const CLIENT_SSL = 1 << 11;
const CLIENT_IGNORE_SIGPIPE = 1 << 12;
const CLIENT_TRANSACTIONS = 1 << 13;
const CLIENT_RESERVED = 1 << 14;
const CLIENT_SECURE_CONNECTION = 1 << 15;
const CLIENT_MULTI_STATEMENTS = 1 << 16;
const CLIENT_MULTI_RESULTS = 1 << 17;
const CLIENT_PS_MULTI_RESULTS = 1 << 18;
const CLIENT_PLUGIN_AUTH = 1 << 19;
const CLIENT_SSL_VERIFY_SERVER_CERT = 1 << 30;
const CLIENT_REMEMBER_OPTIONS = 1 << 31;
const CLIENT_CAPABILITIES = (CLIENT_LONG_PASSWORD | CLIENT_LONG_FLAG | CLIENT_TRANSACTIONS | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION);

// 2^24 - 1 16m
const AUTH_PACK_MAX_LENGTH = 16777215;

// http://dev.mysql.com/doc/internals/en/auth-phase-fast-path.html
// 00 FE
const AUTH_OK_PACK_HEAD = [0, 254];

// FF
const AUTH_ERR_PACK_HEAD = [255];

/**
 * PHP Document Object
 */
class PDO
{
	private $dsn;

	private $sock;

	private $salt;

	private $flag;

	private $username;

	private $password;

	/**
	 * __construct 
	 * 
	 * @param  string $dsn 
	 * @param  string $username 
	 * @param  string $password 
	 * @param  array  $options 
	 * @return void
	 */
	public function __construct($dsn, $username = null, $password = null, $options = [])
	{
		$this->dsn      = new Dsn($dsn);
		$this->username = $username;
		$this->password = $password;
		$this->sock     = $this->connect($options);

		$this->flag = CLIENT_CAPABILITIES ;
		if($this->dsn->dbname)
		{
			$this->flag |= CLIENT_CONNECT_WITH_DB;
		}
	}

	/**
	 * Connect MySQL
	 * 
	 * @return void
	 */
	public function connect()
	{
		$this->sock = new ngx_socket_tcp();

		$this->sock->connect($this->dsn->host, $this->dsn->port);

		$pack = $this->_readPacket();
		$protocolVersion = ord($pack[0]);

		$length = strlen($pack);
		$serverVersion = '';
		for($i = 1; $i < $length; $i++)
		{
			if($pack[$i] === chr(0))
			{
				$i++;
				break;
			}
			else
			{
				$serverVersion .= $pack[$i];
			}
		}

		$connectionId = $pack[$i] . $pack[++$i] . $pack[++$i] . $pack[++$i];
		$i++;

		//salt_1 (8)
        $salt = '';
        for($j = $i; $j < $i+8; $j++) 
		{
            $salt .= $pack[$j];
        }
        $i = $i + 8;

        //filler_1 (1) -- 0x00
        $i++;

        //capability_flag_1 (2) -- lower 2 bytes of the CapabilityFlags (optional)
        $i = $i + 2;

        //character_set (1) -- default server character-set, only the lower 8-bits CharacterSet (optional)
        $characterSet = $pack[$i];
        $i++;

        //status_flags (2) --StatusFlags (optional)
        $i = $i + 2;

        //capability_flags_2 (2) -- upper 2 bytes of the CapabilityFlags
        $i = $i + 2;

        //saltLen (1) -- length of the combined auth_plugin_data, if auth_plugin_data_len is > 0
        $saltLen = ord($pack[$i]);
        $i++;
        $saltLen = max(12, $saltLen - 9);
        
		//filling
        $i = $i + 10;

        //next salt
        if ($length >= $i + $saltLen)
        {
            for($j = $i; $j < $i + $saltLen; $j++)
            {
                $salt .= $pack[$j];
            }
        }
        $authPluginName = '';
        $i = $i + $saltLen + 1;
        for($j = $i; $j<$length-1; $j++)
		{
            $authPluginName .= $pack[$j];
        }

		$this->salt = $salt;
		$result = $this->auth($this->flag, $this->username, $this->password, $this->salt, $this->dsn->dbname);

		var_dump($result);
		exit;
	}

	public function auth($flag, $user, $pass, $salt, $db = '')
	{
        $data = pack('L', $flag);

        // max-length 4bytes, 16M
        $data .= pack('L', AUTH_PACK_MAX_LENGTH);

        // Charset 1byte utf8=>33
        $data .= chr(33);

        // filling, 23bytes
		for($i=0; $i<23; $i++)
		{
            $data .= chr(0);
        }

        // http://dev.mysql.com/doc/internals/en/secure-password-authentication.html#packet-Authentication::Native41
		$token    = sha1($pass, true);
        $scramble = $token ^ sha1($salt . sha1($token, true), true);

		// user + scramble
        $data .= $user . chr(0) . chr(strlen($scramble)) . $scramble;
		if($db)
		{
            $data .= $db . chr(0);
        }

		$this->_sendPacket($data);
		$pack = $this->_readPacket();

        $head = ord($pack[0]);

        if(in_array($head, AUTH_OK_PACK_HEAD))
		{
            return ['status' => true, 'code' => 0, 'msg' => ''];
        }
		else
		{
            $error_code = unpack("v", $pack[1] . $pack[2])[1];
            $error_msg  = '';
            for($i = 3; $i < strlen($pack); $i++)
			{
                $error_msg .= $pack[$i];
            }
			return ['status' => false, 'code' => $error_code, 'msg' => $error_msg];
        }
    }

	private function _sendPacket($data)
	{
        $str = pack("L", strlen($data));
        $s   = $str[0] . $str[1] . $str[2];
		$this->sock->send($s . chr(1) . $data);
	}

	private function _readPacket()
	{
		$data = $this->sock->receive();
		$len  = unpack("L", $data[0] . $data[1] . $data[2]. chr(0))[1];

		$seq = unpack("C", $data[3])[1];

		return substr($data, 4);
	}

	public function query($query)
	{
	}

	public function fetch()
	{
	}

	public function exec()
	{
	}

	public function lastInsertId()
	{
	}
}


/**
 * Connecting to database
 * 
 */
class Dsn
{
	public $protocol;

	public $host;

	public $dbname;

	public function __construct($dsn)
	{
		$parts = explode(":", $dsn);
		if ((count($parts)) !== 2)
		{
			throw new Exception("Uncaught PDOException: invalid data source name");
		}
		else if($parts[0] !== 'mysql')
		{
			throw new Exception("Uncaught PDOException: could not find driver");
		}
		else
		{
			$this->protocol = 'mysql';
		}

		// params
		$this->host   = '127.0.0.1';
		$this->dbname = '';
		$this->port   = 3306;

		$params = explode(';', $parts[1]);
		foreach($params as $param)
		{
			$kv = explode('=', $param);
			if(count($kv) !== 2)
			{
				throw new Exception("Invalid parameter: $param");
			}

			switch($kv[0])
			{
			case 'host':
				$this->host = $kv[1];
				break;
			case 'dbname':
				$this->dbname = $kv[1];
				break;
			case 'port':
				$this->port = $kv[1];
				break;
			}
		}
	}
}
