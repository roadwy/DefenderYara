
rule Trojan_BAT_Blocker_SDF_MTB{
	meta:
		description = "Trojan:BAT/Blocker.SDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {61 11 06 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c 00 11 05 17 58 13 05 } //00 00 
	condition:
		any of ($a_*)
 
}