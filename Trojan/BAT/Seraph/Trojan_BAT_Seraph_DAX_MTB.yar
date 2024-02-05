
rule Trojan_BAT_Seraph_DAX_MTB{
	meta:
		description = "Trojan:BAT/Seraph.DAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {11 02 2a 00 28 90 01 01 00 00 06 13 00 38 00 00 00 00 28 90 01 01 00 00 0a 11 00 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 13 01 38 00 00 00 00 02 11 01 28 90 01 01 00 00 06 13 02 38 00 00 00 00 dd 90 00 } //02 00 
		$a_01_1 = {42 00 68 00 62 00 76 00 74 00 61 00 77 00 61 00 66 00 6d 00 68 00 } //00 00 
	condition:
		any of ($a_*)
 
}