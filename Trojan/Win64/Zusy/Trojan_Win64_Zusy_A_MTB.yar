
rule Trojan_Win64_Zusy_A_MTB{
	meta:
		description = "Trojan:Win64/Zusy.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 85 c0 79 1d 49 8b 4c 24 08 49 2b 0c 24 48 c1 f9 05 48 ff c9 49 63 c7 48 3b c1 73 05 41 ff c7 eb 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Zusy_A_MTB_2{
	meta:
		description = "Trojan:Win64/Zusy.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 9c 24 78 01 00 00 48 8b bc 24 50 01 00 00 49 63 e8 40 fe c6 40 c0 ee a0 48 81 c4 58 01 00 00 48 87 ee 66 f7 d5 5e 66 87 ed 5d e9 00 00 00 00 } //1
		$a_01_1 = {80 7f 01 23 e9 05 00 00 00 0f ca 66 f7 d2 48 8d 57 01 e9 00 00 00 00 0f 85 6c 00 00 00 0f b6 57 02 48 3b f4 48 83 c7 02 84 d2 e9 00 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}