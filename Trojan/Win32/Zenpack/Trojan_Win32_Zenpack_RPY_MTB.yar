
rule Trojan_Win32_Zenpack_RPY_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4d fc 8b 91 ac 00 00 00 03 42 3c 8b 4d fc 6b 91 c8 04 00 00 28 8d 84 10 f8 00 00 00 8b 4d fc 89 81 b4 04 00 00 6a 00 8b 55 fc 8b 82 b4 04 00 00 8b 48 10 51 8b 4d fc 83 c1 0c } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpack_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpack.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 c0 80 bd 06 ff ff ff 2e 0f 94 c1 8b 95 e8 fe ff ff 80 3a 54 0f 94 c5 20 e9 f6 c1 01 89 85 ec fe ff ff } //01 00 
		$a_01_1 = {ff d0 83 ec 04 3d 00 00 00 00 0f 94 c1 88 8d e7 fe ff ff 8a 85 e7 fe ff ff a8 01 } //00 00 
	condition:
		any of ($a_*)
 
}