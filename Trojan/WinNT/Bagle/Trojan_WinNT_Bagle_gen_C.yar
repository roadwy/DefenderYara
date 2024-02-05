
rule Trojan_WinNT_Bagle_gen_C{
	meta:
		description = "Trojan:WinNT/Bagle.gen!C,SIGNATURE_TYPE_PEHSTR,15 00 15 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 62 69 73 6f 66 74 } //0a 00 
		$a_01_1 = {5c 5c 2e 5c 73 4b 39 4f 75 30 73 } //0a 00 
		$a_01_2 = {61 76 7a 2e 65 78 65 00 42 61 63 6b 57 65 62 2d 34 34 37 36 38 32 32 2e 65 78 65 00 62 64 61 67 65 6e 74 2e 65 78 65 00 } //01 00 
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 5c 53 76 63 } //00 00 
	condition:
		any of ($a_*)
 
}