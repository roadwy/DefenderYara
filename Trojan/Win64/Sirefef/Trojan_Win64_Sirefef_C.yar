
rule Trojan_Win64_Sirefef_C{
	meta:
		description = "Trojan:Win64/Sirefef.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 81 f8 63 6e 63 74 } //01 00 
		$a_01_1 = {48 c7 45 08 78 56 4f 23 48 89 45 } //01 00 
		$a_01_2 = {41 bb 8a de 67 35 49 03 d1 0f be 0a 45 6b db 21 48 ff c2 44 33 d9 } //01 00 
		$a_01_3 = {73 74 61 74 32 2e 70 68 70 3f 77 3d 25 75 26 69 3d 25 73 26 61 3d } //01 00 
		$a_01_4 = {78 36 34 5c 72 65 6c 65 61 73 65 5c 73 68 65 6c 6c } //03 00 
		$a_01_5 = {74 18 8b 12 81 ea 0b 01 00 00 74 4f 83 fa 01 75 09 48 8b 49 10 e8 5a fe ff ff } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Sirefef_C_2{
	meta:
		description = "Trojan:Win64/Sirefef.C,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 81 f8 63 6e 63 74 } //01 00 
		$a_01_1 = {48 c7 45 08 78 56 4f 23 48 89 45 } //01 00 
		$a_01_2 = {41 bb 8a de 67 35 49 03 d1 0f be 0a 45 6b db 21 48 ff c2 44 33 d9 } //01 00 
		$a_01_3 = {73 74 61 74 32 2e 70 68 70 3f 77 3d 25 75 26 69 3d 25 73 26 61 3d } //01 00 
		$a_01_4 = {78 36 34 5c 72 65 6c 65 61 73 65 5c 73 68 65 6c 6c } //03 00 
		$a_01_5 = {74 18 8b 12 81 ea 0b 01 00 00 74 4f 83 fa 01 75 09 48 8b 49 10 e8 5a fe ff ff } //00 00 
	condition:
		any of ($a_*)
 
}