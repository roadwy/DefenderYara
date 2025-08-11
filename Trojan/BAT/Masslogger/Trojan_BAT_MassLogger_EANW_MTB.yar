
rule Trojan_BAT_MassLogger_EANW_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.EANW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 09 11 4f 16 9c 00 11 4f 17 58 13 4f 11 4f 1f 0a 11 09 8e 69 ?? ?? ?? ?? ?? fe 04 13 50 11 50 2d dd } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}