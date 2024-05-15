
rule Trojan_BAT_Injuke_SPDP_MTB{
	meta:
		description = "Trojan:BAT/Injuke.SPDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {38 37 00 00 00 11 03 11 01 28 90 01 03 2b 28 90 01 03 2b 16 11 01 8e 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}