
rule Trojan_BAT_AgenTesla_MBXN_MTB{
	meta:
		description = "Trojan:BAT/AgenTesla.MBXN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 00 74 00 65 00 61 00 6c 00 65 00 72 00 4c 00 69 00 62 00 2e 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 73 00 2e 00 43 00 61 00 70 00 74 00 75 00 72 00 65 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 73 00 } //2 StealerLib.Browsers.CaptureBrowsers
		$a_01_1 = {52 00 65 00 63 00 6f 00 76 00 65 00 72 00 43 00 72 00 65 00 64 00 65 00 6e 00 74 00 69 00 61 00 6c 00 } //2 RecoverCredential
		$a_01_2 = {73 00 6d 00 74 00 70 00 2e 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //2 smtp.gmail.com
		$a_01_3 = {41 45 53 5f 44 65 63 72 79 70 74 6f 72 } //1 AES_Decryptor
		$a_01_4 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_01_5 = {42 69 74 6d 61 70 } //1 Bitmap
		$a_01_6 = {53 63 72 65 65 6e 73 68 6f 74 } //1 Screenshot
		$a_01_7 = {53 6d 74 70 43 6c 69 65 6e 74 } //1 SmtpClient
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=11
 
}