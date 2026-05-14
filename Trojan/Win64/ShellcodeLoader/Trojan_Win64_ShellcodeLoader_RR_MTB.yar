
rule Trojan_Win64_ShellcodeLoader_RR_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeLoader.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 0b 8b c1 83 e1 3f c1 f8 06 6b f1 38 8b 4d 14 c1 e9 10 8b 14 85 80 90 4d 00 32 4c 32 2d 80 e1 01 30 4c 32 2d f6 45 f4 48 75 } //1
		$a_01_1 = {63 6e 73 65 7a 73 74 65 7a 78 6f 64 } //1 cnsezstezxod
		$a_01_2 = {61 71 79 65 76 69 64 67 6d 69 61 6e 6a 71 62 69 77 64 6a 70 66 64 74 72 61 } //1 aqyevidgmianjqbiwdjpfdtra
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}