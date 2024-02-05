
rule Trojan_Win32_Trickbot{
	meta:
		description = "Trojan:Win32/Trickbot,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 54 24 0c 8b 4c 24 04 85 d2 74 47 33 c0 8a 44 24 08 57 8b f9 83 fa 04 72 2d f7 d9 83 e1 03 74 08 2b d1 88 07 47 49 75 fa 8b c8 c1 e0 08 03 c1 8b c8 c1 e0 10 03 c1 8b ca 83 e2 03 c1 e9 02 74 06 f3 ab 85 d2 74 06 88 07 47 4a 75 fa 8b 44 24 08 5f c3 } //01 00 
		$a_02_1 = {55 8b ec 8b 45 0c 81 ec 6c 90 01 01 00 00 56 8b 75 08 57 3d 11 01 00 00 0f 87 e6 01 00 00 0f 84 7a 01 00 00 8b c8 49 74 3e 49 74 29 83 e9 0d 0f 85 ec 01 00 00 8d 45 94 50 56 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}