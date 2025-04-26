
rule Backdoor_Win64_Lotok_GMF_MTB{
	meta:
		description = "Backdoor:Win64/Lotok.GMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 8b ce 44 2b cf 41 ff c1 41 f7 f9 45 8b 08 8d 04 17 8b d6 48 98 49 8d 0c 86 41 8b 04 86 41 89 00 4d 8b c6 44 89 09 8b cf } //10
		$a_01_1 = {66 89 45 d8 0f b6 05 8e 46 24 00 f2 0f 11 45 d0 0f 29 4d c0 88 45 da } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}