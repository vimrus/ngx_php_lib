<?php
/* curl */
const CURLOPT_URL            = 0x00;
const CURLOPT_RETURNTRANSFER = 0x01;
const CURLOPT_HEADER         = 0x02;
const CURLOPT_HTTPGET        = 0x03;
const CURLOPT_POST           = 0x04;
const CURLOPT_POSTFIELDS     = 0x05;
const CURLOPT_CUSTOMREQUEST  = 0x06;

class Resource
{
	private $sock;

	private $url;

	private $port;

	private $host;

	private $path;

	private $method;	

	private $postData;

	private $file;

	private $returnTransfer;

	public function __construct($url)
	{
		$this->url    = $url;
		$this->port   = 80;
		$this->method = 'GET';
		$this->path   = '/';

		$this->sock   = new ngx_socket_tcp();
	}

	public function setOpt($type, $value)
	{
		switch($type)
		{
		case CURLOPT_URL:
			$this->url = $value;
			break;
		case CURLOPT_RETURNTRANSFER:
			$this->returnTransfer = $value;
			break;
		case CURLOPT_HTTPGET:
			if($value == true)
			{
				$this->method = 'GET';
			}
			break;
		case CURL_POST:
			if($value == true)
			{
				$this->method = 'POST';
			}
			break;
		case CURLOPT_POSTFIELDS:
			$this->postData = $value;
			break;
		case CURLOPT_CUSTOMREQUEST:
			$this->method = $value;
			break;
		case CURLOPT_FILE:
			$this->out = $value;
			break;
		case CURL_PUT:
			if($value == true)
			{
				$this->method = 'PUT';
			}
			break;
		case CURL_HEADER:
			break;
		}
	}

	public function exec()
	{
		$parsedURL = parse_url($this->url);
		if(!$parsedURL)
		{
			throw new Exception("URL error");
		}

		if(isset($parsedURL['host']))  $this->host  = $parsedURL['host'];
		if(isset($parsedURL['port']))  $this->port  = $parsedURL['port'];
		if(isset($parsedURL['path']))  $this->path  = $parsedURL['path'];
		if(isset($parsedURL['query'])) $this->query = $parsedURL['query'];

		$this->sock->connect($this->host, $this->port);
		$string = $this->method . ' ' . $this->path . " HTTP/1.1\r\nHost: " . $this->host . "\r\nConnection: keep-alive\r\n\r\n";
		$this->sock->send($string);
		$output = $this->sock->receive();
		if($this->file)
		{
			return fwrite($this->file, $output);
		}
		else
		{
			if($this->returnTransfer)
			{
				return $output;
			}
			else
			{
				echo $output;
			}
		}
	}

	public function close()
	{
		return $this->sock->close();
	}
}

function curl_init($url = null)
{
	return new Resource($url);
}

function curl_getinfo()
{
}

function curl_setopt($ch, $type, $value)
{
	$ch->setOpt($type, $value);
}

function curl_exec($ch)
{
	return $ch->exec();
}

function curl_close($ch)
{
	return $ch->close();
}
