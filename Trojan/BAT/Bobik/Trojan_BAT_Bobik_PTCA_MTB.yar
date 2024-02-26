
rule Trojan_BAT_Bobik_PTCA_MTB{
	meta:
		description = "Trojan:BAT/Bobik.PTCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 16 12 00 28 90 01 01 00 00 0a 6f 44 00 00 0a 7e 08 00 00 04 72 48 02 00 70 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 6f 46 00 00 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}