APP��Ŀ�û����봫��һֱû����HTTPS�����ǵ��û�����˽��ʱ����AES��������ܣ��Ժ�Ҳ���������ֻ��������˼��ܽ�����

PHP����Ѱ�phpAES��Ŀ���ֻ��˽�����ֲ��ԡ�

�ò���������PHP ANDROID IOS���໥�ӽ���������AES�����㷨���롣

PHP��AES�����㷨��

```php
    class MCrypt {
		private $hex_iv = '00000000000000000000000000000000'; # converted JAVA byte code in to HEX and placed it here           
		private $key = 'U1MjU1M0FDOUZ.Qz'; #Same as in JAVA
		function __construct() {
			$this->key = hash('sha256', $this->key, true);
			//echo $this->key.'<br/>';
		}
		function encrypt($str) {   
			$td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
			mcrypt_generic_init($td, $this->key, $this->hexToStr($this->hex_iv));
			$block = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
			$pad = $block - (strlen($str) % $block);
			$str .= str_repeat(chr($pad), $pad);
			$encrypted = mcrypt_generic($td, $str);
			mcrypt_generic_deinit($td);
			mcrypt_module_close($td);    
			return base64_encode($encrypted);
		}
		function decrypt($code) {    
			$td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
			mcrypt_generic_init($td, $this->key, $this->hexToStr($this->hex_iv));
			$str = mdecrypt_generic($td, base64_decode($code));
			$block = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
			mcrypt_generic_deinit($td);
			mcrypt_module_close($td);    
			return $this->strippadding($str);           
		}
		/*
		  For PKCS7 padding
		 */
		private function addpadding($string, $blocksize = 16) {
			$len = strlen($string);
			$pad = $blocksize - ($len % $blocksize);
			$string .= str_repeat(chr($pad), $pad);
			return $string;
		}
		private function strippadding($string) {
			$slast = ord(substr($string, -1));
			$slastc = chr($slast);
			$pcheck = substr($string, -$slast);
			if (preg_match("/$slastc{" . $slast . "}/", $string)) {
				$string = substr($string, 0, strlen($string) - $slast);
				return $string;
			} else {
				return false;
			}
		}
		function hexToStr($hex)
		{
			$string='';
			for ($i=0; $i < strlen($hex)-1; $i+=2)
			{
				$string .= chr(hexdec($hex[$i].$hex[$i+1]));
			}
			return $string;
		}
	}
	
	$encryption = new MCrypt();
	echo $encryption->encrypt('123456') . "<br/>";
	echo $encryption->decrypt('tpyxISJ83dqEs3uw8bN/+w==');
	
	 ```
	 
	 
	 
	 java��AES�����㷨��
	 
	 ```java
	 
	import javax.crypto.Cipher;
	import javax.crypto.spec.IvParameterSpec;
	import javax.crypto.spec.SecretKeySpec;
	import android.util.Base64;
	/**
	 * @author vipin.cb , vipin.cb@experionglobal.com <br>
	 *         Sep 27, 2013, 5:18:34 PM <br>
	 *         Package:- <b>com.veebow.util</b> <br>
	 *         Project:- <b>Veebow</b>
	 *         <p>
	 */
	public class AESCrypt {
		private final Cipher cipher;
		private final SecretKeySpec key;
		private AlgorithmParameterSpec spec;
		public static final String SEED_16_CHARACTER = "U1MjU1M0FDOUZ.Qz";
		public AESCrypt() throws Exception {
			// hash password with SHA-256 and crop the output to 128-bit for key
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			digest.update(SEED_16_CHARACTER.getBytes("UTF-8"));
			byte[] keyBytes = new byte[32];
			System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);
			cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
			key = new SecretKeySpec(keyBytes, "AES");
			spec = getIV();
		}
		public AlgorithmParameterSpec getIV() {
			byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, };
			IvParameterSpec ivParameterSpec;
			ivParameterSpec = new IvParameterSpec(iv);
			return ivParameterSpec;
		}
		public String encrypt(String plainText) throws Exception {
			cipher.init(Cipher.ENCRYPT_MODE, key, spec);
			byte[] encrypted = cipher.doFinal(plainText.getBytes("UTF-8"));
			String encryptedText = new String(Base64.encode(encrypted,
					Base64.DEFAULT), "UTF-8");
			return encryptedText;
		}
		public String decrypt(String cryptedText) throws Exception {
			cipher.init(Cipher.DECRYPT_MODE, key, spec);
			byte[] bytes = Base64.decode(cryptedText, Base64.DEFAULT);
			byte[] decrypted = cipher.doFinal(bytes);
			String decryptedText = new String(decrypted, "UTF-8");
			return decryptedText;
		}
	}
	
	 ```
	 
	 
	IOS��AES�����㷨��
	 
	https://github.com/Gurpartap/AESCrypt-ObjC
	 
	stackoverflow�ο�
	http://stackoverflow.com/questions/5928915/wanted-compatible-aes-code-encrypt-decrypt-for-iphone-android-windows-xp

	http://stackoverflow.com/questions/19196728/aes-128-encryption-in-java-decryption-in-php