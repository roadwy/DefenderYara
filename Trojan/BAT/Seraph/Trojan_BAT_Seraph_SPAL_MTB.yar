
rule Trojan_BAT_Seraph_SPAL_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SPAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 03 00 "
		
	strings :
		$a_03_0 = {09 06 02 28 90 01 03 06 14 14 14 6f 90 01 03 0a 26 00 16 2d ea 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}