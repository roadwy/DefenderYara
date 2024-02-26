
rule Trojan_BAT_Seraph_SPDV_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SPDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {06 28 01 00 00 2b 28 02 00 00 2b 28 51 00 00 0a 02 7b 15 00 00 04 03 04 58 07 58 6f 8d 00 00 06 6f 52 00 00 0a 28 03 00 00 2b 25 2d 02 } //00 00 
	condition:
		any of ($a_*)
 
}