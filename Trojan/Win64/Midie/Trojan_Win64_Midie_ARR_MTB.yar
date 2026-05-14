
rule Trojan_Win64_Midie_ARR_MTB{
	meta:
		description = "Trojan:Win64/Midie.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 c1 0f b6 c0 8a 0c 04 30 0e 48 ff c6 48 83 ef } //12
		$a_03_1 = {33 d0 8b c5 83 e0 ?? 03 d7 41 8b 0c 86 03 cd 33 d1 44 2b c2 } //8
	condition:
		((#a_01_0  & 1)*12+(#a_03_1  & 1)*8) >=20
 
}