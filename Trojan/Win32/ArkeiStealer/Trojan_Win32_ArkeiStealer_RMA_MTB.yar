
rule Trojan_Win32_ArkeiStealer_RMA_MTB{
	meta:
		description = "Trojan:Win32/ArkeiStealer.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c4 89 84 24 90 01 04 55 8b ac 24 90 01 04 56 57 33 f6 33 ff 3b de 7e 90 01 01 81 fb 85 02 00 00 75 90 02 08 ff 15 90 02 10 e8 90 01 04 30 04 2f 83 fb 19 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_ArkeiStealer_RMA_MTB_2{
	meta:
		description = "Trojan:Win32/ArkeiStealer.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 f6 85 ff 7e 90 01 01 55 8b 2d 90 01 04 8b ff 83 ff 2d 75 90 01 01 6a 00 6a 00 6a 00 6a 00 6a 00 ff d5 6a 00 6a 00 6a 00 6a 00 ff 15 90 01 04 e8 90 01 04 30 04 1e 81 ff 91 05 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}