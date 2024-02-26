
rule Trojan_Win32_MysticStealer_ASAY_MTB{
	meta:
		description = "Trojan:Win32/MysticStealer.ASAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {ff d6 80 34 2f 90 01 01 ff d6 80 04 2f 90 01 01 ff d6 ff d6 80 04 2f 90 01 01 ff d6 80 04 2f 90 01 01 ff d6 80 04 2f 90 00 } //05 00 
		$a_03_1 = {ff d6 80 34 2f 90 01 01 ff d6 80 04 2f 90 01 01 ff d6 80 04 2f 90 01 01 ff d6 47 3b fb 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}