
rule Trojan_BAT_MassLogger_RDA_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 07 13 05 11 05 6f 80 00 00 0a 13 06 73 81 00 00 0a 0d 09 11 06 17 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}