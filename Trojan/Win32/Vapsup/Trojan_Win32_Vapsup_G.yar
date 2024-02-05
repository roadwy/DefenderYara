
rule Trojan_Win32_Vapsup_G{
	meta:
		description = "Trojan:Win32/Vapsup.G,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {2d 4c 49 42 47 43 43 57 33 32 2d 45 48 2d 32 2d 53 4a 4c 4a 2d 47 54 48 52 2d 4d 49 4e 47 57 33 32 } //01 00 
		$a_02_1 = {8b 45 0c 89 04 24 e8 90 01 02 ff ff 90 02 04 0f b7 90 02 02 35 90 01 02 00 00 90 02 03 89 44 24 04 8b 4d 08 89 0c 24 c7 45 90 01 02 00 00 00 e8 90 01 03 00 8b 45 90 00 } //01 00 
		$a_02_2 = {8b 4d 0c 89 0c 24 e8 90 01 02 ff ff 90 02 03 0f b7 c0 35 90 01 02 00 00 89 45 98 8b 02 8b 40 f4 89 45 94 8b 55 94 b8 fe ff ff 1f 29 d0 83 f8 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}