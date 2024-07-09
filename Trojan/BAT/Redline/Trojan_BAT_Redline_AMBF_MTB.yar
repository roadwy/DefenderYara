
rule Trojan_BAT_Redline_AMBF_MTB{
	meta:
		description = "Trojan:BAT/Redline.AMBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {03 1f 10 28 ?? 00 00 2b 1f 20 28 ?? 00 00 2b 28 ?? 00 00 2b 13 02 } //2
		$a_01_1 = {53 65 71 75 65 6e 63 65 45 71 75 61 6c } //1 SequenceEqual
		$a_01_2 = {48 4d 41 43 53 48 41 32 35 36 } //1 HMACSHA256
		$a_01_3 = {41 65 73 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 AesCryptoServiceProvider
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}