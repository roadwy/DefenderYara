
rule Trojan_BAT_Seraph_AALF_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AALF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {06 8e 69 8d 90 01 01 00 00 01 0b 16 0c 38 90 01 01 00 00 00 07 08 06 08 91 72 90 01 01 00 00 70 28 90 01 01 00 00 0a 59 d2 9c 08 17 58 0c 08 06 8e 69 32 e4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}