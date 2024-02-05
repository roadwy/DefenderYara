
rule Trojan_Win32_Delf_JE{
	meta:
		description = "Trojan:Win32/Delf.JE,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {33 d2 33 c9 8a 50 02 33 db 8a 48 01 8a 18 89 5d f4 83 c0 03 8b 1c 96 8b 7d f4 03 9c 8e 00 04 00 00 03 9c be 00 08 00 00 8b 7d e8 c1 fb 10 } //01 00 
		$a_00_1 = {66 69 6c 65 63 6f 75 6e 74 00 00 00 ff ff ff ff 0c 00 00 00 64 6f 77 6e 6c 6f 61 64 66 69 6c 65 } //01 00 
		$a_00_2 = {44 69 72 65 63 74 6f 72 79 5c 73 68 65 6c 6c 5c 66 69 6e 64 5c 64 64 65 65 78 65 63 } //01 00 
		$a_02_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 90 02 10 64 65 6c 6c 69 73 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}