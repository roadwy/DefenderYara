
rule Trojan_Win32_Zusy_MA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {eb 7e d8 ca d8 c3 d8 e7 89 12 d8 d7 d8 cd d8 ce d8 db d8 c0 d8 c0 89 11 d8 ed d8 d9 d8 df d8 c3 d8 d9 d8 e5 d8 c3 d8 ed d8 c1 d8 c4 89 0a d8 c3 } //0a 00 
		$a_01_1 = {46 47 42 48 4e 4a 4d 4b 2e 44 4c 4c } //01 00 
		$a_01_2 = {46 66 67 62 48 67 79 62 68 } //01 00 
		$a_01_3 = {46 67 62 79 68 6e 4b 6a 67 76 } //01 00 
		$a_01_4 = {54 74 66 76 79 67 62 4b 68 62 67 66 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zusy_MA_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 69 6f 73 6a 68 39 38 77 34 67 6f 69 77 34 6a 73 65 72 6a 68 } //02 00 
		$a_01_1 = {69 6f 73 6f 67 33 34 39 38 67 73 65 6a 6f 69 73 65 69 6a 68 } //02 00 
		$a_01_2 = {66 6f 72 6b 35 2e 64 6c 6c } //02 00 
		$a_01_3 = {73 68 69 62 6f 73 6a 65 67 39 38 34 67 69 6f 73 65 72 68 6a 73 65 72 } //02 00 
		$a_01_4 = {73 69 6f 67 73 6a 72 69 6f 67 34 39 38 67 73 6a 69 6f 65 68 6a 65 } //01 00 
		$a_01_5 = {53 65 74 54 68 72 65 61 64 41 66 66 69 6e 69 74 79 4d 61 73 6b } //01 00 
		$a_01_6 = {47 65 74 50 72 6f 63 65 73 73 57 6f 72 6b 69 6e 67 53 65 74 53 69 7a 65 45 78 } //00 00 
	condition:
		any of ($a_*)
 
}