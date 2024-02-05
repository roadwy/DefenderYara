
rule Trojan_Win32_GandCrab_PVS_MTB{
	meta:
		description = "Trojan:Win32/GandCrab.PVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 02 00 "
		
	strings :
		$a_02_0 = {69 c0 09 3c 04 00 8d 73 01 a3 90 01 04 a1 90 01 04 0f af c6 69 c0 85 ba 03 00 a3 90 09 05 00 a1 90 00 } //01 00 
		$a_02_1 = {30 04 3e 46 3b 74 24 10 7c 90 09 05 00 e8 90 00 } //01 00 
		$a_02_2 = {c7 45 fc 43 94 0e 00 81 45 fc 80 0a 18 00 69 05 90 01 04 fd 43 03 00 03 45 fc a3 90 00 } //01 00 
		$a_02_3 = {30 84 37 00 fe ff ff 6a 00 ff 15 90 09 05 00 e8 90 00 } //01 00 
		$a_02_4 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 90 09 05 00 a1 90 00 } //02 00 
		$a_00_5 = {8a 4a 03 8a c1 24 fc 8a d9 80 e1 f0 c0 e1 02 0a 0a c0 e0 04 0a 42 01 c0 e3 06 0a 5a 02 88 0c 3e } //00 00 
	condition:
		any of ($a_*)
 
}