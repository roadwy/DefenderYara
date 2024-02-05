
rule Trojan_Win32_Delf_LK{
	meta:
		description = "Trojan:Win32/Delf.LK,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 4a 65 74 53 77 61 70 } //01 00 
		$a_00_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 73 61 66 65 73 75 72 66 2e 65 78 65 } //01 00 
		$a_00_2 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 76 69 64 65 6f 73 32 } //01 00 
		$a_02_3 = {2e 31 67 62 2e 72 75 2f 90 02 10 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}