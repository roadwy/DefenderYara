
rule Trojan_BAT_Strictor_NA_MTB{
	meta:
		description = "Trojan:BAT/Strictor.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {11 2a 61 19 11 1f 58 61 11 2e 61 d2 } //00 00 
	condition:
		any of ($a_*)
 
}