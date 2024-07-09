
rule Backdoor_Win64_Vankul_A{
	meta:
		description = "Backdoor:Win64/Vankul.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 44 8b d3 41 be bf e5 f1 78 48 8b 50 18 48 83 c2 10 48 8b 0a } //1
		$a_03_1 = {41 33 c0 44 69 c0 ?? ?? ?? ?? 41 8b c0 c1 e8 0f 44 33 c0 } //1
		$a_01_2 = {41 be 0f 66 02 00 4c 8d 7f 04 4c 89 75 58 41 b9 04 00 00 00 } //1
		$a_01_3 = {8a 44 05 48 30 02 49 03 d4 4d 2b f4 75 } //1
		$a_01_4 = {ff d6 48 8d 87 44 6d 00 00 48 8d 4d 48 ff d0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}