
rule Trojan_BAT_Avemaria_KAC_MTB{
	meta:
		description = "Trojan:BAT/Avemaria.KAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 06 11 07 11 05 11 07 28 90 01 01 00 00 06 20 90 01 02 00 00 61 d1 9d 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}