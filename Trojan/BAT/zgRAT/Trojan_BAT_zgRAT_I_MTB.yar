
rule Trojan_BAT_zgRAT_I_MTB{
	meta:
		description = "Trojan:BAT/zgRAT.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 00 0a 06 06 6f 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 13 06 90 00 } //02 00 
		$a_03_1 = {09 11 05 16 11 05 8e 69 6f 90 01 01 00 00 0a 08 6f 90 01 01 00 00 0a 13 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}