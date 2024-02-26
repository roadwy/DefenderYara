
rule Trojan_BAT_Mamut_KAF_MTB{
	meta:
		description = "Trojan:BAT/Mamut.KAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0a 02 16 06 6e 28 90 01 01 00 00 0a 02 8e 69 28 90 01 01 00 00 0a 00 06 6e 28 90 01 01 00 00 0a 02 8e 69 6a 28 90 01 01 00 00 0a 7e 90 01 01 00 00 04 12 01 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}