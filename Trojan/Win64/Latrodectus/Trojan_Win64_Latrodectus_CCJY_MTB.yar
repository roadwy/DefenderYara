
rule Trojan_Win64_Latrodectus_CCJY_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.CCJY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 28 48 8b 4c 24 58 48 03 c8 48 8b c1 0f b6 00 48 63 4c 24 20 0f b6 4c 0c 30 33 c1 48 8b 4c 24 28 48 8b 54 24 58 48 03 d1 48 8b ca 88 01 e9 } //6
		$a_01_1 = {65 78 74 72 61 00 66 6f 6c 6c 6f 77 65 72 00 72 75 6e 00 73 63 75 62 } //4
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*4) >=10
 
}