
rule Trojan_Win32_MysticStealer_MBJH_MTB{
	meta:
		description = "Trojan:Win32/MysticStealer.MBJH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff d6 80 04 2f 90 01 01 ff d6 80 34 2f 90 01 01 ff d6 ff d6 80 04 2f 90 01 01 ff d6 80 04 2f 90 01 01 47 3b fb 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}