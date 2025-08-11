
rule Trojan_BAT_MassLogger_WL_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.WL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0b 14 0c 73 16 00 00 0a 0d 73 17 00 00 0a 13 04 11 04 09 06 07 6f 18 00 00 0a 17 73 19 00 00 0a 13 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}