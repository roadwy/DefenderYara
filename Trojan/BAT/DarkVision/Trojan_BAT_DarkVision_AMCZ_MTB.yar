
rule Trojan_BAT_DarkVision_AMCZ_MTB{
	meta:
		description = "Trojan:BAT/DarkVision.AMCZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 07 6f ?? 00 00 0a 09 08 6f ?? 00 00 0a 09 6f ?? 00 00 0a 06 16 06 8e 69 6f ?? 00 00 0a 13 04 de } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}