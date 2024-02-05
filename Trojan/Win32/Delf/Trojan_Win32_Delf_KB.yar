
rule Trojan_Win32_Delf_KB{
	meta:
		description = "Trojan:Win32/Delf.KB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 75 f4 8b 07 8a 44 18 ff 8b d0 8b 4d f8 8a 4c 31 ff 32 d1 81 e2 ff 00 00 00 8b f2 85 f6 75 90 01 01 8b f0 81 e6 ff 00 00 00 8b c7 e8 90 00 } //01 00 
		$a_00_1 = {77 69 6e 6e 65 77 64 6c 6c 2e 64 6c 6c } //01 00 
		$a_00_2 = {77 69 6e 64 6f 77 73 70 72 6f 78 79 2e 6f 72 67 2f 77 69 6e 2e 6c 61 63 } //01 00 
		$a_00_3 = {63 73 73 2f 6c 6f 67 73 2f 61 64 64 2e 70 68 70 } //00 00 
	condition:
		any of ($a_*)
 
}