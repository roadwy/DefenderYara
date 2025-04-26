
rule Trojan_Win64_Mikey_GVT_MTB{
	meta:
		description = "Trojan:Win64/Mikey.GVT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {8e 1f 1b 74 e2 dc 8a 3f 28 26 3e 32 f9 13 ca } //5
		$a_01_1 = {34 0d 89 50 ed 53 31 b0 a6 ba } //5
		$a_01_2 = {12 73 fd 33 58 a9 32 7f 54 5a 46 f3 c0 3a 65 f3 31 48 e6 49 66 38 22 92 } //10
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*10) >=10
 
}