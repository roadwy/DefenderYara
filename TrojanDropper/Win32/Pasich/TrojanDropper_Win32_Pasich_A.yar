
rule TrojanDropper_Win32_Pasich_A{
	meta:
		description = "TrojanDropper:Win32/Pasich.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 1c 0f b6 55 10 03 55 fc 8b 45 08 03 45 fc 0f be 08 33 ca 8b 55 08 03 55 fc 88 0a eb d3 } //01 00 
		$a_00_1 = {5c 00 5c 00 3f 00 5c 00 67 00 6c 00 6f 00 62 00 61 00 6c 00 72 00 6f 00 6f 00 74 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 72 00 6f 00 6f 00 74 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6c 00 62 00 64 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00 5c 00 78 00 30 00 30 00 } //01 00  \\?\globalroot\systemroot\system32\clbdll.dll\x00
		$a_00_2 = {5c 00 5c 00 3f 00 5c 00 67 00 6c 00 6f 00 62 00 61 00 6c 00 72 00 6f 00 6f 00 74 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 72 00 6f 00 6f 00 74 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 63 00 6c 00 62 00 64 00 72 00 69 00 76 00 65 00 72 00 2e 00 73 00 79 00 73 00 5c 00 78 00 30 00 30 00 } //01 00  \\?\globalroot\systemroot\system32\drivers\clbdriver.sys\x00
		$a_01_3 = {63 6c 62 49 6d 61 67 65 44 61 74 61 00 } //00 00 
	condition:
		any of ($a_*)
 
}