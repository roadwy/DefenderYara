
rule Trojan_Win32_Delf_KU{
	meta:
		description = "Trojan:Win32/Delf.KU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {63 5c 68 6f 73 74 73 90 09 1e 00 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 90 00 } //01 00 
		$a_02_1 = {6f 00 2f 00 3f 00 69 00 73 00 6c 00 65 00 6d 00 3d 00 68 00 6f 00 73 00 74 00 73 00 26 00 67 00 75 00 76 00 65 00 6e 00 6c 00 69 00 6b 00 3d 00 64 00 77 00 6d 00 90 09 08 00 2e 00 69 00 6e 00 66 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}