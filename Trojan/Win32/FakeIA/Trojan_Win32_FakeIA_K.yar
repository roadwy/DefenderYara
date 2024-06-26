
rule Trojan_Win32_FakeIA_K{
	meta:
		description = "Trojan:Win32/FakeIA.K,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {49 6e 62 6f 75 6e 64 00 90 02 0c 41 6c 6c 6f 77 20 74 68 69 73 20 49 50 00 90 02 0c 42 6c 6f 63 6b 20 74 68 69 73 20 49 50 00 90 00 } //02 00 
		$a_01_1 = {66 00 72 00 6d 00 50 00 44 00 32 00 30 00 30 00 39 00 41 00 6c 00 65 00 72 00 74 00 00 00 } //01 00 
		$a_03_2 = {61 6c 6c 6f 77 74 68 69 73 70 6f 72 74 00 90 02 03 62 6c 6f 63 6b 61 6c 6c 69 70 73 68 6f 76 65 72 00 90 00 } //02 00 
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 50 44 65 66 65 6e 64 65 72 } //01 00  SOFTWARE\Microsoft\PDefender
		$a_00_4 = {41 00 4c 00 4c 00 4f 00 57 00 54 00 48 00 49 00 53 00 50 00 4f 00 52 00 54 00 48 00 4f 00 56 00 45 00 52 00 0b 00 42 00 4c 00 4f 00 43 00 4b 00 41 00 4c 00 4c 00 49 00 50 00 53 00 } //00 00 
	condition:
		any of ($a_*)
 
}