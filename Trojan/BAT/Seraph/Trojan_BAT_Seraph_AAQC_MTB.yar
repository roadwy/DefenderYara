
rule Trojan_BAT_Seraph_AAQC_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAQC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {11 01 11 01 11 03 94 11 01 11 02 94 58 20 00 01 00 00 5d 94 13 08 } //00 00 
	condition:
		any of ($a_*)
 
}