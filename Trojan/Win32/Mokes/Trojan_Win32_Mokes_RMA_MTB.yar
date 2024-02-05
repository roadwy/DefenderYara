
rule Trojan_Win32_Mokes_RMA_MTB{
	meta:
		description = "Trojan:Win32/Mokes.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 f6 85 ff 7e 90 01 01 81 ff 85 02 00 00 75 90 01 01 6a 00 6a 00 6a 00 6a 00 ff 15 90 01 04 8b 44 24 90 01 01 8d 0c 06 e8 90 01 04 30 01 46 3b f7 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Mokes_RMA_MTB_2{
	meta:
		description = "Trojan:Win32/Mokes.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 8b 6c 24 90 01 01 81 3d 90 01 04 c7 0f 00 00 75 90 01 01 6a 90 01 01 6a 90 01 01 6a 90 01 01 6a 90 01 01 ff 15 90 01 04 a1 90 01 04 69 c0 fd 43 03 00 05 90 01 04 a3 90 01 04 8a 0d 90 01 04 30 0c 37 83 fb 19 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}