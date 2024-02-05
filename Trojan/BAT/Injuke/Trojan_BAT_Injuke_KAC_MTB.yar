
rule Trojan_BAT_Injuke_KAC_MTB{
	meta:
		description = "Trojan:BAT/Injuke.KAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {11 01 11 02 11 00 11 02 91 20 90 01 06 00 00 06 28 90 01 01 00 00 06 59 d2 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}