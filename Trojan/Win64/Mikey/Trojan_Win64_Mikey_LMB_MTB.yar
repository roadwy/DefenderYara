
rule Trojan_Win64_Mikey_LMB_MTB{
	meta:
		description = "Trojan:Win64/Mikey.LMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 7c 24 24 83 c9 ff 33 c0 8b f7 f2 ae f7 d1 49 6a 01 8b e9 8d 4c 24 18 55 } //15
		$a_01_1 = {8b 44 24 10 8b 54 24 38 8b c8 c1 e9 10 89 0a 8b 4c 24 3c 25 ff ff 00 00 89 01 } //10
		$a_01_2 = {8b 44 24 08 81 ec 28 06 00 00 53 8b d9 56 57 8b 73 08 8b 7b 04 8b 53 0c 8b c8 46 03 fa 8b d1 89 73 08 8b b4 24 38 06 00 00 c1 e9 02 f3 a5 8b ca 83 e1 03 } //5
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=30
 
}