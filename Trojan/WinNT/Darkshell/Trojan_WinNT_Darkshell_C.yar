
rule Trojan_WinNT_Darkshell_C{
	meta:
		description = "Trojan:WinNT/Darkshell.C,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {b9 4e e6 40 bb 74 04 3b c1 75 1a a1 28 0c 01 00 8b 00 35 80 0d 01 00 a3 80 0d 01 00 75 07 8b c1 } //01 00 
		$a_01_1 = {ff 35 94 0d 01 00 ff 35 8c 0d 01 00 ff 15 20 0c 01 00 0f b7 05 a0 0d 01 00 50 ff 35 a4 0d 01 00 } //01 00 
		$a_01_2 = {25 ff ff fe ff 0f 22 c0 8b 06 89 03 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 33 db eb 1b bb 0d 00 00 } //01 00 
		$a_01_3 = {61 00 73 00 67 00 66 00 64 00 73 00 67 00 65 00 74 00 79 00 79 00 74 00 68 00 75 00 74 00 72 00 73 00 66 00 61 00 65 00 65 00 32 00 33 00 34 00 35 00 36 00 34 00 35 00 36 00 6a 00 74 00 79 00 6a 00 36 00 37 00 75 00 72 00 36 00 79 00 72 00 68 00 74 00 79 00 } //01 00 
		$a_01_4 = {5c 00 3f 00 3f 00 5c 00 44 00 61 00 72 00 6b 00 32 00 31 00 31 00 38 00 } //01 00 
		$a_01_5 = {5c 00 64 00 45 00 76 00 49 00 63 00 45 00 5c 00 56 00 6f 00 69 00 63 00 65 00 44 00 65 00 76 00 69 00 63 00 65 00 } //01 00 
		$a_01_6 = {5f 64 61 72 6b 73 68 65 6c 6c 5c 69 33 38 36 5c 44 61 72 6b 53 68 65 6c 6c 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}