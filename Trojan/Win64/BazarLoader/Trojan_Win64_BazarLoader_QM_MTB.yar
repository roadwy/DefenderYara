
rule Trojan_Win64_BazarLoader_QM_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.QM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 "
		
	strings :
		$a_00_0 = {b8 01 00 00 00 83 c0 00 eb 00 48 83 c4 18 c3 48 89 4c 24 08 48 83 ec 18 eb 00 8b 44 24 28 89 04 24 eb dd 44 89 4c 24 20 4c 89 44 24 18 eb 0b } //10
		$a_81_1 = {76 45 34 48 50 4e 51 44 63 57 31 71 52 6f } //3 vE4HPNQDcW1qRo
		$a_81_2 = {61 78 36 34 2e 64 6c 6c } //3 ax64.dll
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3) >=16
 
}
rule Trojan_Win64_BazarLoader_QM_MTB_2{
	meta:
		description = "Trojan:Win64/BazarLoader.QM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {48 89 44 24 70 48 8d 84 24 ac 00 00 00 48 89 44 24 78 48 8b 4c 24 78 48 8d 94 24 98 00 00 00 48 89 94 24 80 00 00 00 48 8b 8c 24 80 00 00 00 48 c7 02 90 01 04 4c 8d 8c 24 b0 00 00 00 4c 89 8c 24 88 00 00 00 48 8b 8c 24 88 00 00 00 48 8b 4c 24 48 48 83 c1 18 48 89 8c 24 90 01 04 48 8b 8c 24 90 01 04 48 63 09 49 89 09 48 8b 4c 24 48 48 83 c1 10 48 89 4c 24 50 48 8b 4c 24 50 4c 8b 01 48 8b 4c 24 70 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}