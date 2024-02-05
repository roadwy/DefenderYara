
rule PWS_BAT_Stimilina_I{
	meta:
		description = "PWS:BAT/Stimilina.I,SIGNATURE_TYPE_PEHSTR_EXT,2d 00 2d 00 09 00 00 14 00 "
		
	strings :
		$a_01_0 = {53 00 74 00 65 00 61 00 6c 00 43 00 6f 00 6e 00 66 00 69 00 67 00 73 00 53 00 73 00 66 00 6e 00 42 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 } //14 00 
		$a_01_1 = {2f 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2f 00 53 00 74 00 65 00 61 00 6d 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 2e 00 76 00 64 00 66 00 } //01 00 
		$a_01_2 = {41 00 6c 00 6c 00 53 00 61 00 76 00 65 00 64 00 50 00 72 00 6f 00 66 00 69 00 6c 00 65 00 73 00 2e 00 74 00 78 00 74 00 } //01 00 
		$a_01_3 = {41 00 6c 00 6c 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 2e 00 74 00 78 00 74 00 } //01 00 
		$a_01_4 = {4f 00 6e 00 20 00 43 00 6f 00 70 00 69 00 65 00 20 00 4d 00 75 00 6c 00 74 00 69 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 } //01 00 
		$a_01_5 = {4f 00 6e 00 20 00 43 00 6f 00 70 00 69 00 65 00 20 00 4d 00 75 00 6c 00 74 00 69 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 73 00 } //01 00 
		$a_01_6 = {53 00 65 00 6e 00 64 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 } //01 00 
		$a_01_7 = {42 00 72 00 6f 00 77 00 73 00 65 00 72 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 2e 00 7a 00 69 00 70 00 } //01 00 
		$a_01_8 = {47 00 72 00 61 00 62 00 54 00 78 00 74 00 4f 00 6e 00 44 00 65 00 73 00 6b 00 54 00 6f 00 70 00 } //00 00 
		$a_00_9 = {87 10 00 00 52 6d 73 3b 49 90 9e c9 3b e7 d9 be 20 e4 06 00 87 10 00 00 3a da a9 49 09 04 b5 98 a4 3f 81 91 e0 ca 03 00 87 10 } //00 00 
	condition:
		any of ($a_*)
 
}