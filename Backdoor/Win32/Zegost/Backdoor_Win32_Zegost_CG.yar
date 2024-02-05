
rule Backdoor_Win32_Zegost_CG{
	meta:
		description = "Backdoor:Win32/Zegost.CG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4d fc 80 04 11 da 03 ca 8b 4d fc 80 34 11 29 03 ca 42 3b d0 7c e9 } //01 00 
		$a_01_1 = {c6 45 f4 48 c6 45 f5 61 c6 45 f6 63 c6 45 f7 6b c6 45 f8 65 c6 45 f9 72 } //01 00 
		$a_01_2 = {c6 45 c6 50 c6 45 c7 72 c6 45 c8 6f c6 45 c9 63 c6 45 ca 65 c6 45 cb 73 c6 45 cc 73 c6 45 cd 49 c6 45 ce 64 88 5d cf ff d6 50 ff d7 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Zegost_CG_2{
	meta:
		description = "Backdoor:Win32/Zegost.CG,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0b 00 00 0a 00 "
		
	strings :
		$a_01_0 = {47 68 30 73 74 20 55 70 64 61 74 65 } //01 00 
		$a_01_1 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 } //01 00 
		$a_01_2 = {5c 69 6e 73 74 61 6c 6c 2e 64 61 74 } //01 00 
		$a_01_3 = {5c 73 79 73 6c 6f 67 2e 64 61 74 } //01 00 
		$a_01_4 = {53 65 72 76 69 63 65 44 6c 6c } //01 00 
		$a_01_5 = {53 74 61 72 74 53 65 72 76 69 63 65 41 } //01 00 
		$a_01_6 = {57 69 6e 53 74 61 30 5c 44 65 66 61 75 6c 74 } //01 00 
		$a_01_7 = {5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //01 00 
		$a_01_8 = {73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 } //01 00 
		$a_01_9 = {4e 6f 2d 61 64 64 00 00 bd f8 c8 eb 6c 6f 67 69 6e 00 00 00 25 73 20 25 64 00 } //01 00 
		$a_03_10 = {d7 bc b1 b8 b7 a2 cb cd c9 cf cf df d0 c5 cf a2 90 01 18 53 56 43 53 48 4f 53 54 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}