
rule Trojan_BAT_Seraph_SPYU_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SPYU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {08 15 31 0c 07 28 90 01 03 2b 28 02 00 00 2b 0b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}