
rule Trojan_BAT_Njrat_NEB_MTB{
	meta:
		description = "Trojan:BAT/Njrat.NEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 36 11 36 16 72 90 01 01 02 00 70 a2 11 36 17 7e 1b 00 00 04 a2 11 36 18 06 17 9a a2 11 36 19 7e 1b 00 00 04 a2 11 36 1a 17 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}