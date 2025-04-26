
rule Trojan_Win64_Cobaltstrike_HQ_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.HQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 30 fa 80 70 0a fa 48 83 c0 14 4c 39 c0 75 f0 } //10
		$a_01_1 = {80 30 1a 80 70 07 1a 48 83 c0 0e 49 39 c0 75 f0 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}
rule Trojan_Win64_Cobaltstrike_HQ_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.HQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4d 8d 49 01 41 f7 e8 41 8b c8 41 ff c0 d1 fa 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 0f b6 4c 05 ?? 41 30 49 ?? 41 81 f8 ?? ?? ?? ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}