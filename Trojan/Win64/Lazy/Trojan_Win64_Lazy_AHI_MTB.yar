
rule Trojan_Win64_Lazy_AHI_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AHI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 89 74 24 50 48 89 44 24 40 48 c7 44 24 58 00 00 00 00 48 c7 44 24 48 01 00 00 00 c7 44 24 38 28 00 00 00 c7 44 24 30 96 00 00 00 c7 44 24 28 fa 00 00 00 c7 44 24 20 dc 00 00 00 } //5
		$a_01_1 = {4d 8d 48 1f 49 83 e1 e0 4d 8b d9 49 c1 eb 05 47 8b 9c 9a b0 5f 06 00 4d 03 da 41 } //3
		$a_80_2 = {43 68 65 61 74 69 6e 67 20 45 6e 67 69 6e 65 } //Cheating Engine  2
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*3+(#a_80_2  & 1)*2) >=10
 
}