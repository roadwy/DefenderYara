
rule Trojan_Win32_ArkeiStealer_RT_MTB{
	meta:
		description = "Trojan:Win32/ArkeiStealer.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 ff 85 db 7e 90 01 01 56 8b 44 24 90 01 01 8d 34 07 e8 90 01 04 30 06 83 fb 19 75 90 01 01 6a 00 6a 00 6a 00 6a 00 ff 15 90 01 04 47 3b fb 7c 90 01 01 5e 5f 81 fb 71 11 00 00 75 90 00 } //01 00 
		$a_03_1 = {83 ff 2d 75 90 01 01 6a 00 6a 00 6a 00 6a 00 6a 00 ff d5 6a 00 ff 15 90 01 04 e8 90 01 04 30 04 1e 81 ff 91 05 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}