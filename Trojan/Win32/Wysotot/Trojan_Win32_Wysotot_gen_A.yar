
rule Trojan_Win32_Wysotot_gen_A{
	meta:
		description = "Trojan:Win32/Wysotot.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {63 00 68 00 72 00 6f 00 6d 00 65 00 2e 00 65 00 78 00 65 00 00 90 02 04 6f 00 70 00 65 00 72 00 61 00 2e 00 65 00 78 00 65 00 00 90 02 04 66 00 69 00 72 00 65 00 66 00 6f 00 78 00 2e 00 65 00 78 00 65 00 90 00 } //01 00 
		$a_03_1 = {53 00 74 00 61 00 72 00 74 00 4d 00 65 00 6e 00 75 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 00 90 02 04 73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 90 00 } //01 00 
		$a_01_2 = {65 3a 5c 6c 61 62 73 5c 6f 75 74 5c 76 39 68 6f 6d 65 5f 74 6f 6f 6c 73 5c 52 65 6c 65 61 73 65 5c 76 39 68 74 2e 70 64 62 } //01 00 
		$a_01_3 = {2e 3f 41 56 43 56 39 68 6f 6d 65 5f 74 6f 6f 6c 73 41 70 70 } //01 00 
		$a_01_4 = {2e 00 6c 00 6e 00 6b 00 } //01 00 
		$a_03_5 = {68 6f 6d 65 70 61 67 65 00 90 02 30 68 6f 6d 65 70 61 67 65 5f 63 68 61 6e 67 65 64 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}