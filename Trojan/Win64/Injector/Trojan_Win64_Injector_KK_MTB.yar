
rule Trojan_Win64_Injector_KK_MTB{
	meta:
		description = "Trojan:Win64/Injector.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 94 04 8e 00 00 00 89 d7 40 f6 df 19 c9 83 e1 44 31 ca 41 88 14 02 48 ff c0 48 83 f8 12 } //20
		$a_01_1 = {0f b7 c0 49 ff c3 31 d0 c1 ea 10 69 c0 3b 9f 5d 04 31 c2 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}
rule Trojan_Win64_Injector_KK_MTB_2{
	meta:
		description = "Trojan:Win64/Injector.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 33 c1 48 8b d0 8b c0 48 c1 ea ?? 48 33 d0 41 83 e0 ?? 48 8b c2 49 33 c1 41 be ?? 00 00 00 48 35 ?? ?? ?? ?? 41 8b ce 48 c1 e8 08 41 2a c8 48 33 c2 } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}