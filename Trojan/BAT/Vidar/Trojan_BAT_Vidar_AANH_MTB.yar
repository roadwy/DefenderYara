
rule Trojan_BAT_Vidar_AANH_MTB{
	meta:
		description = "Trojan:BAT/Vidar.AANH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0a 00 25 17 6f 90 01 01 00 00 0a 00 25 18 6f 90 01 01 00 00 0a 00 25 07 6f 90 01 01 00 00 0a 00 13 08 11 08 6f 90 01 01 00 00 0a 13 09 11 09 09 16 09 8e 69 28 90 01 01 00 00 06 13 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}