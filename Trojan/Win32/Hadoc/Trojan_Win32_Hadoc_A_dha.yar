
rule Trojan_Win32_Hadoc_A_dha{
	meta:
		description = "Trojan:Win32/Hadoc.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 52 4d 54 50 61 74 68 25 5c 52 4d 54 5f 53 65 63 75 72 65 42 72 6f 77 73 69 6e 67 2e 65 78 65 } //01 00 
		$a_01_1 = {25 43 75 72 72 65 6e 74 44 72 69 76 65 25 3a 5c 52 4d 54 5f 55 73 65 72 44 61 74 61 5c 25 41 5f 4c 6f 6f 70 46 69 6c 65 4e 61 6d 65 25 } //01 00 
		$a_01_2 = {4b 65 79 62 64 20 68 6f 6f 6b 3a 20 25 73 } //01 00 
		$a_01_3 = {4d 6f 75 73 65 20 68 6f 6f 6b 3a 20 25 73 } //00 00 
	condition:
		any of ($a_*)
 
}