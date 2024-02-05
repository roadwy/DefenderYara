
rule VirTool_Win32_Injector{
	meta:
		description = "VirTool:Win32/Injector,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 59 0d 33 d2 8b c7 f7 f3 8a 59 0c 8a c2 f6 69 0e 8a 16 02 c3 32 d0 88 16 8b 41 04 46 47 3b f8 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Injector_2{
	meta:
		description = "VirTool:Win32/Injector,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 6a 12 59 b8 cc cc cc cc f3 ab 59 89 55 f8 89 } //01 00 
		$a_01_1 = {4d e0 03 48 04 39 4d d0 73 78 8b 4d d0 e8 } //01 00 
		$a_01_2 = {eb 66 83 65 d0 00 6a 2e 5a 8b 4d c0 e8 } //00 00 
		$a_00_3 = {78 } //80 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Injector_3{
	meta:
		description = "VirTool:Win32/Injector,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f bf d0 89 15 68 90 40 00 8b 4d d8 81 c1 aa 38 00 00 a1 64 90 40 00 99 f7 f9 89 55 fc 0f bf 0d 7e 90 40 00 81 c1 a7 00 00 00 8b 45 fc 99 } //01 00 
		$a_01_1 = {0f 9d c2 83 e2 01 0b 55 fc 74 2f 8b 0d 64 90 40 00 81 c1 21 0d 00 00 a1 84 90 40 00 99 f7 f9 0f bf 0d 8a 90 40 00 3b d1 7d 10 0f be 05 91 90 40 00 33 05 68 90 40 00 89 45 fc a1 84 90 40 00 } //00 00 
		$a_00_2 = {7e 15 } //00 00 
	condition:
		any of ($a_*)
 
}