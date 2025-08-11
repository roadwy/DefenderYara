
rule Trojan_Win64_Alevaul_DA_MTB{
	meta:
		description = "Trojan:Win64/Alevaul.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 0b b8 1f 85 eb 51 f7 e9 c1 fa 03 8b c2 c1 e8 1f 03 d0 6b c2 19 2b c8 80 c1 41 88 0b 48 ff c3 49 ff c9 } //10
		$a_01_1 = {44 89 4c 24 60 44 89 54 24 64 48 8b ce 49 8b c0 48 f7 e1 48 8b c1 48 ff c1 48 c1 ea 02 48 6b d2 0d 48 2b c2 8a 44 05 88 30 44 0c 5f 48 83 f9 13 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=10
 
}