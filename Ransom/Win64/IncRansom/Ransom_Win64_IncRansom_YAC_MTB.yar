
rule Ransom_Win64_IncRansom_YAC_MTB{
	meta:
		description = "Ransom:Win64/IncRansom.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_01_0 = {65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 6d 69 6c 69 74 61 72 79 2d 67 72 61 64 65 } //10 encrypted with military-grade
		$a_01_1 = {43 4f 4d 50 55 54 45 52 20 48 41 53 20 42 45 45 4e 20 53 45 49 5a 45 44 } //5 COMPUTER HAS BEEN SEIZED
		$a_01_2 = {70 61 79 20 6d 65 20 62 72 6f } //5 pay me bro
		$a_03_3 = {15 f9 00 00 c7 85 ?? ?? ?? ?? 9c 80 00 00 c7 85 ?? ?? ?? ?? 06 a9 00 00 c7 85 ?? ?? ?? ?? 79 60 01 00 c7 85 ?? ?? ?? ?? f7 cd 00 00 c7 85 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_03_3  & 1)*1) >=21
 
}