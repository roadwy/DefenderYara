
rule Trojan_BAT_Razy_KAC_MTB{
	meta:
		description = "Trojan:BAT/Razy.KAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {61 65 5f 91 04 60 61 d1 9d 06 20 90 01 04 66 66 66 20 90 01 04 61 66 20 90 01 04 61 20 90 01 04 61 66 20 90 01 04 61 66 59 25 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}