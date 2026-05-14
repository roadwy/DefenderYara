
rule Trojan_Win64_Mikey_LMM_MTB{
	meta:
		description = "Trojan:Win64/Mikey.LMM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 8d 4d ff 44 8b c7 42 8b 14 8b 8b cf 41 c1 e0 02 8b c2 c1 e8 05 44 33 c0 c1 e9 03 8b c2 c1 e0 04 33 c8 8b c5 } //20
		$a_01_1 = {41 8b 12 49 03 d1 45 33 c0 8a 02 48 ff c2 41 c1 c8 0e 0f be c0 44 03 c0 8a 02 84 c0 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}