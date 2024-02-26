
rule Trojan_BAT_Seraph_SPXH_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SPXH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {06 07 02 07 91 72 90 01 03 70 28 90 01 03 0a 59 d2 9c 07 17 58 0b 07 02 8e 69 32 e4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}