
rule Trojan_BAT_Seraph_AATW_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AATW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 1b 06 07 02 07 91 20 37 7f 26 0e 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 59 d2 9c 07 17 58 0b 07 02 8e 69 32 df 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}