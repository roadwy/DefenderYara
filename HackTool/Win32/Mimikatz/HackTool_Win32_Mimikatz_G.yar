
rule HackTool_Win32_Mimikatz_G{
	meta:
		description = "HackTool:Win32/Mimikatz.G,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 03 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 5f 72 65 66 6c 65 63 74 69 76 65 5f 6d 69 6d 69 6b 61 74 7a } //powershell_reflective_mimikatz  01 00 
		$a_80_1 = {2e 77 72 69 74 65 70 72 6f 63 65 73 73 6d 65 6d 6f 72 79 2e 69 6e 76 6f 6b 65 } //.writeprocessmemory.invoke  01 00 
		$a_80_2 = {40 28 30 78 34 38 2c 20 30 78 38 39 2c 20 30 78 30 31 2c 20 30 78 34 38 2c 20 30 78 38 39 2c 20 30 78 64 63 2c 20 30 78 35 62 2c 20 30 78 63 33 29 } //@(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)  01 00 
		$a_80_3 = {2d 69 65 71 20 22 64 75 6d 70 63 72 65 64 73 22 } //-ieq "dumpcreds"  01 00 
		$a_80_4 = {2d 69 65 71 20 22 64 75 6d 70 63 65 72 74 73 22 29 } //-ieq "dumpcerts")  01 00 
		$a_80_5 = {69 6d 61 67 65 5f 6e 74 5f 6f 70 74 69 6f 6e 61 6c 5f 68 64 72 36 34 5f 6d 61 67 69 63 27 2c 20 5b 75 69 6e 74 31 36 5d 20 30 78 32 30 62 29 } //image_nt_optional_hdr64_magic', [uint16] 0x20b)  00 00 
	condition:
		any of ($a_*)
 
}