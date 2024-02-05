
rule Trojan_Win32_Delf_UNK_MTB{
	meta:
		description = "Trojan:Win32/Delf.UNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 7a 00 62 00 2e 00 36 00 36 00 77 00 61 00 6e 00 67 00 62 00 61 00 2e 00 63 00 6f 00 6d 00 2f 00 7a 00 68 00 75 00 6f 00 62 00 69 00 61 00 6f 00 } //01 00 
		$a_00_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 33 36 30 63 68 72 6f 6d 65 2e 65 78 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //01 00 
		$a_00_2 = {bf 19 00 02 00 81 cf 00 01 00 00 } //01 00 
		$a_00_3 = {8b 10 85 d2 74 1c c7 00 00 00 00 00 8b 4a f8 49 7c 10 f0 ff 4a f8 75 0a 50 8d 42 f8 } //00 00 
	condition:
		any of ($a_*)
 
}