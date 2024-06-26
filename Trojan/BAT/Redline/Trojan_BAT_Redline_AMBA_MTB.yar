
rule Trojan_BAT_Redline_AMBA_MTB{
	meta:
		description = "Trojan:BAT/Redline.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 02 11 04 73 90 01 01 00 00 0a 11 03 11 01 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 28 90 00 } //01 00 
		$a_01_1 = {48 4d 41 43 53 48 41 32 35 36 } //01 00  HMACSHA256
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_3 = {41 65 73 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //00 00  AesCryptoServiceProvider
	condition:
		any of ($a_*)
 
}