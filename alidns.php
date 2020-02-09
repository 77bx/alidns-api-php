<?php
/***
* Alidns-api-php V1.0
* By Star.Yu
***/
if($_SERVER['REQUEST_METHOD']=="POST"){
  $request = $_POST;
}
if($_SERVER['REQUEST_METHOD']=="GET"){
  $request = $_GET;
}
if(is_array($request)&&count($request)<1){
  Header("Location: http://www.myxzy.com/alidns-api-php.html"); 
  exit('2'); 
}
if(empty($request['id'])){
  exit('2');
}elseif(empty($request['secret'])){
  exit('2');
}elseif(empty($request['domain'])){
  exit('2');
}elseif(empty($request['record'])){
  exit('2');
}else{
  $ip = empty($request['ip']) ? $_SERVER['REMOTE_ADDR'] : addslashes($request['ip']);
  $accessKeyId = addslashes($request['id']);
  $accessKeySecret = addslashes($request['secret']);
  $record = addslashes($request['record']);
  $domain = addslashes($request['domain']);  
}

//公共参数Timestamp GMT时间
$Timestamp = gmdate('Y-m-d\TH:i:s\Z',time());

//Signature percentEncode函数
function percentEncode($str) {
  $res = urlencode($str);
  $res = preg_replace('/\+/', '%20', $res);
  $res = preg_replace('/\*/', '%2A', $res);
  $res = preg_replace('/%7E/', '~', $res);
  return $res;
}

//唯一数，用于防止网络重放攻击
function generateByMicrotime() {
    $microtime = microtime(true);
    $microtime = str_replace('.', '', $microtime);
    return (substr($microtime, 0, 14));
}

//format url
function url($parameters, $accessKeySecret){
  ksort($parameters);
  $canonicalizedQueryString = '';
  foreach ($parameters as $key => $value) {
    $canonicalizedQueryString .= '&' . percentEncode($key) . '=' . percentEncode($value);
  }
  $canonicalizedQueryString = utf8_encode(substr($canonicalizedQueryString, 1));
  $stringToBeSigned = 'POST&%2F&' . percentEncode($canonicalizedQueryString);
  $signature = base64_encode(hash_hmac('sha1', $stringToBeSigned, $accessKeySecret. '&', true));
  $url = 'https://alidns.aliyuncs.com/?' . $canonicalizedQueryString . '&Signature=' . $signature;
  return $url;
}

function ssl_post($url){
  $curl = curl_init(); 
  curl_setopt($curl, CURLOPT_URL, $url);
  curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 0); 
  curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 0); 
  curl_setopt($curl, CURLOPT_POST, 1); 
  curl_setopt($curl, CURLOPT_TIMEOUT, 30); 
	curl_setopt($curl, CURLOPT_HEADER, 0); 
	curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1); 
  $tmpInfo = curl_exec($curl); 
  if (curl_errno($curl)) {
     echo 'Errno'.curl_error($curl);
  }
  curl_close($curl); 
  return $tmpInfo; 
}

$public = array(
  'Format'    =>  'json', 
  'Version' =>    '2015-01-09',
  'SignatureMethod'   =>  'HMAC-SHA1',
  'SignatureNonce'    =>  generateByMicrotime(),
  'AccessKeyId'   =>  $accessKeyId,
  'SignatureVersion'  =>  '1.0',
  'Timestamp' =>  $Timestamp,
  );
$arr = array(  
  'Action'    =>  'DescribeDomainRecords',
  'DomainName'    =>  $domain,
  );

$data = json_decode(ssl_post(url(array_merge($public,$arr), $accessKeySecret)),true);

if(empty($data['DomainRecords'])){
  exit('1');
}else{
  foreach($data['DomainRecords']['Record'] as $value){
    $record_arr = array();
    if($value['RR'] == $record){
      $record_id = $value['RecordId'];
      $record_arr = $value;
      break;
    }
  }
  
  if(empty($record_id)){
    $add = array(
      'Action'    =>  'AddDomainRecord',
      'DomainName'    =>  $domain,
      'RR'    =>  $record,
      'Type'    =>  'A',
      'Value'    =>  $ip,
      'TTL'    =>  '600',
    );
    $data = json_decode(ssl_post(url(array_merge($public,$add), $accessKeySecret)),true);
    if(empty($data['RecordId'])){
      exit('1');
    }else{
      exit('0'); 
    }
  }else{
    if($record_arr['Value'] == $ip){
      exit('0');
    }else{
      $edit = array(
        'Action'    =>  'UpdateDomainRecord',
        'RecordId'    =>  $record_id,
        'RR'    =>  $record,
        'Type'    =>  'A',
        'Value'    =>  $ip,
        'TTL'    =>  '600',
      ); 
      $data = json_decode(ssl_post(url(array_merge($public,$edit), $accessKeySecret)),true);      
      if(empty($data['RecordId'])){
        exit('1');
      }else{
        exit('0'); 
      }    
    } 
  }
}
