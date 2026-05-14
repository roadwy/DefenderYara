
rule Trojan_Win64_XWorm_ARR_MTB{
	meta:
		description = "Trojan:Win64/XWorm.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_03_0 = {4c 21 fb 45 89 fe 41 83 e6 ?? 4c 01 eb 4d 89 f8 49 c1 e8 } //10
		$a_03_1 = {48 8b 4a f8 4c 8d 04 28 49 83 c0 ?? 41 c6 00 ?? 49 89 c1 49 83 f1 } //6
		$a_03_2 = {48 8b 3b 48 8b 73 ?? 48 89 f8 48 f7 d8 4c 8b 7b } //4
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*6+(#a_03_2  & 1)*4) >=20
 
}