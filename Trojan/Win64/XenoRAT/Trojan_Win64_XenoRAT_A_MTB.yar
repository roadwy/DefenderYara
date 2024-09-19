
rule Trojan_Win64_XenoRAT_A_MTB{
	meta:
		description = "Trojan:Win64/XenoRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 ff c0 89 04 24 8b 44 24 28 39 04 24 7d ?? 48 63 04 24 48 8b 4c 24 20 0f b6 04 01 0f b6 4c 24 30 33 c1 48 63 0c 24 48 8b 54 24 20 88 04 0a } //2
		$a_01_1 = {61 48 52 30 63 44 } //4 aHR0cD
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 77 6e 6c 6f 61 64 73 5c } //2 C:\Users\Public\Downloads\
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2) >=8
 
}