<?php
const CLIENT_LONG_PASSWORD          = 1;
const CLIENT_FOUND_ROWS             = 1 << 1;
const CLIENT_LONG_FLAG              = 1 << 2;
const CLIENT_CONNECT_WITH_DB        = 1 << 3;
const CLIENT_NO_SCHEMA              = 1 << 4;
const CLIENT_COMPRESS               = 1 << 5;
const CLIENT_ODBC                   = 1 << 6;
const CLIENT_LOCAL_FILES            = 1 << 7;
const CLIENT_IGNORE_SPACE           = 1 << 8;
const CLIENT_PROTOCOL_41            = 1 << 9;
const CLIENT_INTERACTIVE            = 1 << 10;
const CLIENT_SSL                    = 1 << 11;
const CLIENT_IGNORE_SIGPIPE         = 1 << 12;
const CLIENT_TRANSACTIONS           = 1 << 13;
const CLIENT_RESERVED               = 1 << 14;
const CLIENT_SECURE_CONNECTION      = 1 << 15;
const CLIENT_MULTI_STATEMENTS       = 1 << 16;
const CLIENT_MULTI_RESULTS          = 1 << 17;
const CLIENT_PS_MULTI_RESULTS       = 1 << 18;
const CLIENT_PLUGIN_AUTH            = 1 << 19;
const CLIENT_SSL_VERIFY_SERVER_CERT = 1 << 30;
const CLIENT_REMEMBER_OPTIONS       = 1 << 31;
const CLIENT_CAPABILITIES           = (CLIENT_LONG_PASSWORD | CLIENT_LONG_FLAG | CLIENT_TRANSACTIONS | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION);

const COM_SLEEP               = 0x00;
const COM_QUIT                = 0x01;
const COM_INIT_DB             = 0x02;
const COM_QUERY               = 0x03;
const COM_FIELD_LIST          = 0x04;
const COM_CREATE_DB           = 0x05;
const COM_DROP_DB             = 0x06;
const COM_REFRESH             = 0x07;
const COM_SHUTDOWN            = 0x08;
const COM_STATISTICS          = 0x09;
const COM_PROCESS_INFO        = 0x0A;
const COM_CONNECT             = 0x0B;
const COM_PROCESS_KILL        = 0x0C;
const COM_DEBUG               = 0x0D;
const COM_PING                = 0x0E;
const COM_TIME                = 0x0F;
const COM_DELAYED_INSERT      = 0x10;
const COM_CHANGE_USER         = 0x11;
const COM_BINLOG_DUMP         = 0x12;
const COM_TABLE_DUMP          = 0x13;
const COM_CONNECT_OUT	      = 0x14;
const COM_REGISTER_SLAVE      = 0x15;
const COM_STMT_PREPARE        = 0x16;
const COM_STMT_EXECUTE        = 0x17;
const COM_STMT_SEND_LONG_DATA = 0x18;
const COM_STMT_CLOSE          = 0x19;
const COM_STMT_RESET          = 0x1A;
const COM_SET_OPTION          = 0x1B;
const COM_STMT_FETCH          = 0x1C;

// 2^24 - 1 16m
const AUTH_PACK_MAX_LENGTH = 16777215;

/**
 * PHP Document Object
 */
class PDO
{
	private $serverVersion;

	private $protocolVersion;

	private $dsn;

	private $sock;

	private $scramble;

	// mysql client capabilities
	private $flag;

	private $username;

	private $password;

	private $packetNo;

	const FETCH_ASSOC = 0x00;
	const FETCH_BOTH  = 0x01;
	const FETCH_BOUND = 0x02;
	const FETCH_CLASS = 0x03;
	const FETCH_INTO  = 0x04;
	const FETCH_LAZY  = 0x05;
	const FETCH_NUM   = 0x06;
	const FETCH_OBJ   = 0x07;

	const FETCH_ORI_NEXT  = 0x08;
	const FETCH_ORI_PRIOR = 0x09;
	const FETCH_ORI_FIRST = 0x0A;
	const FETCH_ORI_LAST  = 0x0A;
	const FETCH_ORI_ABS   = 0x0B;
	const FETCH_ORI_REL   = 0x0C;

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
		$this->flag     = CLIENT_CAPABILITIES ;

		if($this->dsn->dbname)
		{
			$this->flag |= CLIENT_CONNECT_WITH_DB;
		}

		$this->connect($options);

		return $this;
	}

	/**
	 * Connect MySQL
	 * 
	 * @return void
	 */
	public function connect($options)
	{
		$this->sock = new ngx_socket_tcp();

		$this->sock->connect($this->dsn->host, $this->dsn->port);

		list($pack, $type) = $this->_readPacket();
		if($type == 'ERR')
		{
			list($code, $msg) = $this->_parseErrPacket($pack);
			throw new Exception("error " . $code . ': ' . $msg);
		}

		$this->protocolVersion = ord($pack[0]);

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
		$this->serverVersion = $serverVersion;

		$connectionId = $pack[$i] . $pack[++$i] . $pack[++$i] . $pack[++$i];
		$i++;

		// scramble_1 (8)
		$scramble = '';
		for($j = $i; $j < $i+8; $j++)
		{
			$scramble .= $pack[$j];
		}
		$i = $i + 8;

		// filler_1 (1) -- 0x00
		$i++;

		// capability_flag_1 (2) -- lower 2 bytes of the CapabilityFlags (optional)
		$i = $i + 2;

		// character_set (1) -- default server character-set, only the lower 8-bits CharacterSet (optional)
		$characterSet = $pack[$i];
		$i++;

		// status_flags (2) --StatusFlags (optional)
		$i = $i + 2;

		// capability_flags_2 (2) -- upper 2 bytes of the CapabilityFlags
		$i = $i + 2;

		// scrambleLen (1) -- length of the combined auth_plugin_data, if auth_plugin_data_len is > 0
		$scrambleLen = ord($pack[$i]);
		$i++;
		$scrambleLen = max(12, $scrambleLen - 9);

		// filler
		$i = $i + 10;

		// scramble_2
		if($length >= $i + $scrambleLen)
		{
			for($j = $i; $j < $i + $scrambleLen; $j++)
			{
				$scramble .= $pack[$j];
			}
		}
		$authPluginName = '';
		$i = $i + $scrambleLen + 1;
		for($j = $i; $j<$length-1; $j++)
		{
			$authPluginName .= $pack[$j];
		}

		$this->scramble = $scramble;
		$this->auth($this->flag, $this->username, $this->password, $this->scramble, $this->dsn->dbname);
	}

	public function auth($flag, $user, $pass, $scramble, $db = '')
	{
		$data = pack('L', $flag);

		// max-length 4bytes, 16M
		$data .= pack('L', AUTH_PACK_MAX_LENGTH);

		// charset 1byte, utf8=>33
		$data .= chr(33);

		// filler, 23bytes
		for($i=0; $i<23; $i++)
		{
			$data .= chr(0);
		}

		// http://dev.mysql.com/doc/internals/en/secure-password-authentication.html#packet-Authentication::Native41
		$hash  = sha1($pass, true);
		$token = $hash ^ sha1($scramble . sha1($hash, true), true);

		// user + token 
		$data .= $user . chr(0) . chr(strlen($token)) . $token;
		if($db)
		{
			$data .= $db . chr(0);
		}
		else
		{
			$data .= chr(0);
		}

		$this->_sendPacket($data);
		list($pack, $type) = $this->_readPacket();

		if($type == 'ERR')
		{
			list($code, $msg) = $this->_parseErrPacket($pack);
			throw new Exception("error " . $code . ': ' . $msg);
		}
		return true;
	}

	/**
	 * _sendPacket
	 *
	 * @param  string $data
	 * @access private
	 * @return void
	 */
	private function _sendPacket($data)
	{
		$str = pack("L", strlen($data));
		$s   = $str[0] . $str[1] . $str[2];

		$this->packetNo++;

		$this->sock->send($s . chr($this->packetNo) . $data);
	}

	private function _readPacket()
	{
		$pack = $this->sock->receive();
		return $this->_parsePacket($pack);
	}

	private function _parsePacket($pack)
	{
		$len = unpack("L", $pack[0] . $pack[1] . $pack[2]. chr(0))[1];

		$this->packetNo = unpack("C", $pack[3])[1];

		$data = substr($pack, 4);
		$head = ord($data[0]);

		switch($head)
		{
		case 0x00:
			$type = 'OK';
			break;
		case 0xff:
			$type = 'ERR';
			break;
		case 0xfe:
			$type = 'EOF';
			break;
		default:
			$type = 'DATA';
		}
		return [$data, $type];
	}

	private function _parseErrPacket($data)
	{
		$errCode = unpack("v", $data[1] . $data[2])[1];
		$errMsg  = '';
		for($i = 3; $i < strlen($data); $i++)
		{
			$errMsg.= $data[$i];
		}
		return [$errCode, $errMsg];
	}

	private function _parseResultPacket($data)
	{
		// result set header package
		$pos = 0;
		list($fieldCount, $pos) = $this->_parseLengthCodedBin($data, $pos);
		$extra = $this->_parseLengthCodedBin($data, $pos);

		$cols = [ 'name' => [], 'type' => [] ];

		// field package
		for($i = 0; $i < $fieldCount; $i++)
		{
			list($data, $type) = $this->_parsePacket(substr($data, $pos));
			$pos = 0;

			list($catalog, $pos)  = $this->_parseLengthCodedString($data, $pos);
			list($db, $pos)       = $this->_parseLengthCodedString($data, $pos);
			list($table, $pos)    = $this->_parseLengthCodedString($data, $pos);
			list($orgTable, $pos) = $this->_parseLengthCodedString($data, $pos);
			list($colName, $pos)  = $this->_parseLengthCodedString($data, $pos);
			list($orgName, $pos)  = $this->_parseLengthCodedString($data, $pos);

			$pos++; // ignore filler

			list($charset, $pos) = $this->_getByte2($data, $pos);
			list($len, $pos)  = $this->_getByte4($data, $pos);
			list($type, $pos) = $this->_getByte($data, $pos);
			list($flag, $pos) = $this->_getByte2($data, $pos);
			list($decimals, $pos) = $this->_getByte($data, $pos);

			$pos += 2; // ignore filler

			$cols['name'][] = $colName;
			$cols['type'][] = $type;
		}

		// eof
		$data = substr($data, $pos);
		list($data, $type) = $this->_parsePacket($data);
		if($type != 'EOF')
		{
			throw new Exception('unexpected packet type' . $type . 'while eof packet is expected');
		}
		else
		{
			$pos = 1;
			list($warningCount, $pos) = $this->_getByte2($data, $pos);
			list($status, $pos) = $this->_getByte2($data, $pos);
		}

		// row data
		$rows = [];
		while(true)
		{
			$data = substr($data, $pos);
			list($data, $type) = $this->_parsePacket($data);
			if($type == 'EOF')
			{
				$pos = 1;
				list($warningCount, $pos) = $this->_getByte2($data, $pos);
				list($status, $pos) = $this->_getByte2($data, $pos);
				break;
			}

			$row = [];
			$pos = 0;
			for($i = 0; $i < $fieldCount; $i++)
			{
				list($value, $pos) = $this->_parseLengthCodedString($data, $pos);
				$row[] = $value;
			}

			$rows[] = $row;
		}
		return [$cols, $rows];
	}

	public function query($statement, $fetchStyle = PDO::FETCH_BOTH)
	{
		$this->packetNo = -1;

		$this->_sendPacket(chr(COM_QUERY) . $statement, 0);
		list($pack, $type) = $this->_readPacket();
		if($type == 'ERR')
		{
			list($code, $msg) = $this->_parseErrPacket($pack);
			throw new Exception("error " . $code . ': ' . $msg);
		}
		list($cols, $rows) = $this->_parseResultPacket($pack);

		$stmt = new PDOStatement($statement, $cols, $rows, $fetchStyle);
		return $stmt;
	}

	private function _getByte($data, $pos)
	{
		$count = unpack("S", $data[$pos] . chr(0))[1];
		$pos++;
		return [$count, $pos];
	}

	private function _getByte2($data, $pos)
	{
		$count = unpack("S", $data[$pos] . $data[$pos+1])[1];
		$pos   = $pos + 2;
		return [$count, $pos];
	}

	private function _getByte3($data, $pos)
	{
		$count = unpack("L", $data[$pos] . $data[$pos+1] . $data[$pos+2] . chr(0))[1];
		$pos   = $pos + 3;
		return [$count, $pos];
	}

	private function _getByte4($data, $pos)
	{
		$count = unpack("L", $data[$pos] . $data[$pos+1] . $data[$pos+2] . $data[$pos+3])[1];
		$pos   = $pos + 4;
		return [$count, $pos];
	}

	private function _getByte8($data, $pos)
	{
		$low   = unpack("L", $data[$pos] . $data[$pos+1] . $data[$pos+2] . $data[$pos+3])[1];
		$high  = unpack("L", $data[$pos+4] . $data[$pos+5] . $data[$pos+6] . $data[$pos+7])[1];
		$count = $high*4294967296 + $low;
		$pos   = $pos + 8;
		return [$count, $pos];
	}

	private function _parseLengthCodedBin($data, $pos)
	{
		$first = ord($data[$pos]);
		switch($first)
		{
		case 0:
			$pos++;
			return [0, $pos];
			break;
		case 251:
			$pos++;
			return [0, $pos];
			break;
		case 252:
			$pos++;
			return $this->_getByte2($data, $pos);
			break;
		case 253:
			$pos++;
			return $this->_getByte3($data, $pos);
			break;
		case 254:
			$pos++;
			return $this->_getByte8($data, $pos);
			break;
		default:
			$pos++;
			return [$first, $pos];
		}
	}

	private function _parseLengthCodedString($data, $pos)
	{
		list($len, $pos) = $this->_parseLengthCodedBin($data, $pos);
		return [substr($data, $pos, $len), $pos + $len];
	}

	public function exec()
	{
	}

	public function lastInsertId()
	{
	}
}

/**
 * PDOStatement
 */
class PDOStatement implements IteratorAggregate
{
	public $queryString;

	private $data = [];

	private $offset;

	private $rows;

	private $cols;

	public function __construct($queryString, $cols, $rows, $fetchStyle)
	{
		$this->queryString = $queryString;
		$this->offset      = -1;
		$this->cols        = $cols;
		$this->rows        = $rows;
		$this->fetchStyle  = $fetchStyle;
	}

	public function getIterator()
	{
		switch($this->fetchStyle)
		{
		case PDO::FETCH_NUM:
			return new ArrayIterator($this->rows);
			break;
		case PDO::FETCH_ASSOC:
			$result = [];
			foreach($this->rows as $row)
			{
				$data = [];
				foreach($this->cols['name'] as $key => $name)
				{
					$data[$name] = $row[$key];
				}
				$result[] = $data;
			}
			return new ArrayIterator($result);
			break;
		case PDO::FETCH_BOTH:
			$result = [];
			foreach($this->rows as $row)
			{
				$data = [];
				foreach($this->cols['name'] as $key => $name)
				{
					$data[$name] = $row[$key];
					$data[$key]  = $row[$key];
				}
				$result[] = $data;
			}
			return new ArrayIterator($result);
			break;
		case PDO::FETCH_OBJ:
			$result = [];
			foreach($this->rows as $row)
			{
				$data = new stdClass();
				foreach($this->cols['name'] as $key => $name)
				{
					$data->$name = $row[$key];
				}
				$result[] = $data;
			}
			return new ArrayIterator($result);
			break;
		}
	}

	public function fetch($fetchStyle = PDO::FETCH_BOTH, $cursorOrientation = PDO::FETCH_ORI_NEXT, $cursorOffset = 0)
	{
		switch($cursorOrientation)
		{
		case PDO::FETCH_ORI_NEXT:
			if(++$this->offset >= count($this->rows)) return false;
			break;
		}

		$row = $this->rows[$this->offset];

		switch($fetchStyle)
		{
		case PDO::FETCH_NUM:
			return $row;
			break;
		case PDO::FETCH_ASSOC:
			$result = [];
			foreach($this->cols['name'] as $key => $name)
			{
				$result[$name] = $row[$key];
			}
			return $result;
			break;
		case PDO::FETCH_BOTH:
			foreach($this->cols['name'] as $key => $name)
			{
				$row[$name] = $row[$key];
			}
			return $row;
			break;
		case PDO::FETCH_OBJ:
			$result = new stdClass();
			foreach($this->cols['name'] as $key => $name)
			{
				$result->$name = $row[$key];
			}
			return $result;
			break;
		case PDO::FETCH_CLASS:
			break;
		case PDO::FETCH_BOUND:
			break;
		case PDO::FETCH_INTO:
			break;
		case PDO::FETCH_LAZY:
			break;
		}
	}

	public function fetchAll($fetchStyle = PDO::FETCH_BOTH)
	{
		switch($fetchStyle)
		{
		case PDO::FETCH_NUM:
			return $this->rows;
			break;
		case PDO::FETCH_ASSOC:
			$result = [];
			foreach($this->rows as $row)
			{
				$data = [];
				foreach($this->cols['name'] as $key => $name)
				{
					$data[$name] = $row[$key];
				}
				$result[] = $data;
			}
			return $result;
			break;
		case PDO::FETCH_BOTH:
			$result = [];
			foreach($this->rows as $row)
			{
				$data = [];
				foreach($this->cols['name'] as $key => $name)
				{
					$data[$name] = $row[$key];
					$data[$key]  = $row[$key];
				}
				$result[] = $data;
			}
			return $result;
			break;
		case PDO::FETCH_OBJ:
			$result = [];
			foreach($this->rows as $row)
			{
				$data = new stdClass();
				foreach($this->cols['name'] as $key => $name)
				{
					$data->$name = $row[$key];
				}
				$result[] = $data;
			}
			return $result;
			break;
		}
	}
}

/**
 * Connecting to database
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

		// default
		$this->host   = '127.0.0.1';
		$this->dbname = '';
		$this->port   = 3306;

		// params: k1=v1;k2=v2
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
