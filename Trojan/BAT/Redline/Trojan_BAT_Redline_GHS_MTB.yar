
rule Trojan_BAT_Redline_GHS_MTB{
	meta:
		description = "Trojan:BAT/Redline.GHS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 73 ?? ?? ?? 0a 13 05 11 05 11 04 6f ?? ?? ?? 0a 11 05 18 6f ?? ?? ?? 0a 11 05 18 6f ?? ?? ?? 0a 11 05 6f ?? ?? ?? 0a 13 06 11 06 07 16 07 8e 69 6f ?? ?? ?? 0a 13 07 28 ?? ?? ?? 0a 11 07 6f ?? ?? ?? 0a 13 08 11 08 6f ?? ?? ?? 0a 13 0a de 0d 13 09 11 09 6f 60 00 00 0a 13 0a de 00 } //10
		$a_01_1 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 TripleDESCryptoServiceProvider
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}