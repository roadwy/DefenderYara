
rule Trojan_Win32_Zenpack_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 48 42 39 4e 37 36 32 43 33 83 c4 04 eb 03 50 47 4e 59 8b 0f ff 77 08 8b 45 00 03 cb 51 8b cd ff 10 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpack_RPZ_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpack.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 c0 80 bd 06 ff ff ff 2e 0f 94 c1 8b 95 e4 fe ff ff 80 3a 54 0f 94 c5 20 e9 f6 c1 01 89 85 f0 fe ff ff } //01 00 
		$a_01_1 = {ff d0 83 ec 0c 8d 8d fc fe ff ff c7 85 f8 fe ff ff ff ff ff ff 81 c1 03 00 00 00 80 bd ff fe ff ff 53 89 85 e8 fe ff ff 89 8d e4 fe ff ff } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpack_RPZ_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpack.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 85 9c fc ff ff ff d1 83 ec 0c 8b 8d a4 fc ff ff 66 81 39 53 00 0f 94 c3 8b 95 a0 fc ff ff 66 81 3a 45 00 0f 94 c7 20 fb 8b b5 b8 fc ff ff 66 81 3e 2e 00 0f 94 c7 20 fb 8b bd a8 fc ff ff 66 81 3f 4c 00 0f 94 c7 } //01 00 
		$a_01_1 = {89 85 94 fc ff ff ff d1 83 ec 0c 8b 8d 9c fc ff ff 66 81 39 53 00 0f 94 c3 8b 95 98 fc ff ff 66 81 3a 45 00 0f 94 c7 20 fb 8b b5 b0 fc ff ff 66 81 3e 2e 00 0f 94 c7 20 fb 8b bd a0 fc ff ff 66 81 3f 4c 00 0f 94 c7 } //00 00 
	condition:
		any of ($a_*)
 
}