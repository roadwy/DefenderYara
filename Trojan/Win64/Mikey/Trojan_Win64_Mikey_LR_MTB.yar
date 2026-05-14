
rule Trojan_Win64_Mikey_LR_MTB{
	meta:
		description = "Trojan:Win64/Mikey.LR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {42 8b 0c 83 b8 05 15 00 00 49 03 c9 0f b6 11 85 d2 } //15
		$a_01_1 = {c0 e1 04 48 8b c7 49 f7 e2 41 0a c8 48 c1 ea 03 48 8d 04 d2 49 8b d2 48 2b d0 32 0c 32 41 88 0c 1a 49 ff c2 4d 3b d1 } //10
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}