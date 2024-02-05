
rule VirTool_Win32_Injector_BD{
	meta:
		description = "VirTool:Win32/Injector.BD,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 79 6c 69 74 6f 6c 20 6b 6e 6f 77 73 20 74 68 65 20 61 6e 73 77 65 72 2e } //01 00 
		$a_01_1 = {42 74 77 2c 20 54 48 45 20 47 41 4d 45 2e } //01 00 
		$a_01_2 = {28 59 6f 75 20 6a 75 73 74 20 6c 6f 73 74 20 69 74 2e 29 } //01 00 
		$a_00_3 = {33 c9 b9 06 41 40 00 8a 01 3c 99 75 02 eb 0b 2b 05 04 10 40 00 88 01 41 eb ed } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Injector_BD_2{
	meta:
		description = "VirTool:Win32/Injector.BD,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 04 00 00 0e 00 "
		
	strings :
		$a_03_0 = {68 00 00 32 40 6a 00 68 00 00 00 40 6a 00 ff 15 90 01 04 dc 8d 90 01 04 df e0 a8 0d 0f 85 90 01 01 90 04 01 03 03 2d 04 00 00 dd 9d 90 01 01 fe ff ff 90 01 1f 68 00 00 28 40 6a 00 68 00 00 00 40 6a 00 ff 15 90 00 } //01 00 
		$a_03_1 = {c7 45 fc 22 00 00 00 8b 90 01 02 03 90 01 02 0f 80 90 01 01 02 00 00 89 90 01 02 c7 45 fc 23 00 00 00 8b 90 01 02 99 f7 7d 90 01 01 89 90 00 } //01 00 
		$a_03_2 = {c7 45 fc 08 00 00 00 83 bd 90 01 01 ff ff ff 1a 0f 8c 90 01 01 00 00 00 83 bd 90 01 01 ff ff ff 33 0f 8f 90 01 01 00 00 00 c7 45 fc 09 00 00 00 90 00 } //01 00 
		$a_03_3 = {ff 1a 0f 8c 90 01 01 00 00 00 83 bd 90 01 01 ff ff ff 33 0f 8f 90 01 01 00 00 00 c7 45 fc 90 01 01 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}