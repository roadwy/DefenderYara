
rule Trojan_BAT_MassLogger_GN_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {01 0b 07 72 90 01 03 70 6f 90 01 03 0a 14 72 90 01 03 70 17 8d 90 01 03 01 25 16 72 90 01 03 70 a2 14 14 28 90 01 03 0a 74 90 01 03 01 0c 00 08 14 1a 8d 90 01 03 01 25 d0 90 01 03 04 28 90 01 03 0a 73 90 01 03 0a 72 90 01 03 70 28 90 01 03 0a 18 8d 90 01 03 01 25 17 03 a2 14 14 28 90 01 03 0a 26 72 90 01 04 0d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_BAT_MassLogger_GN_MTB_2{
	meta:
		description = "Trojan:BAT/MassLogger.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {17 0c 19 8d 90 01 03 01 13 06 11 06 16 7e 90 01 03 04 a2 11 06 17 7e 90 01 03 04 a2 11 06 18 20 90 01 04 28 90 01 03 06 a2 11 06 73 90 01 03 06 90 02 20 2a 90 00 } //1
		$a_02_1 = {17 13 05 17 13 06 19 8d 90 01 03 01 13 07 11 07 16 7e 90 01 03 04 a2 11 07 17 7e 90 01 03 04 a2 11 07 18 72 90 01 04 a2 11 07 73 90 01 03 06 90 02 20 2a 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}