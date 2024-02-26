
rule Trojan_BAT_Seraph_ASAT_MTB{
	meta:
		description = "Trojan:BAT/Seraph.ASAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {01 0d 08 09 16 1a 6f 90 01 01 00 00 0a 26 09 16 28 90 01 01 00 00 0a 13 04 08 16 73 90 01 01 00 00 0a 13 05 11 04 8d 90 01 01 00 00 01 13 06 11 05 11 06 16 11 04 6f 90 01 01 00 00 0a 26 11 06 13 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}