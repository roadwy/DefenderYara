
rule Trojan_BAT_Njrat_NEC_MTB{
	meta:
		description = "Trojan:BAT/Njrat.NEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {06 07 16 06 6f 21 00 00 0a 6f 54 00 00 0a 6f 55 00 00 0a 28 56 00 00 0a 28 35 00 00 0a 0d 11 04 17 d6 13 04 11 04 11 05 31 d5 } //00 00 
	condition:
		any of ($a_*)
 
}