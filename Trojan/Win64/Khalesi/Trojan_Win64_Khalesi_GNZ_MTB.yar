
rule Trojan_Win64_Khalesi_GNZ_MTB{
	meta:
		description = "Trojan:Win64/Khalesi.GNZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 89 c1 45 31 c0 31 d2 4c 8d 64 24 42 31 c9 48 89 de e8 } //10
		$a_03_1 = {56 53 48 83 ec 50 48 8b 2d 90 01 04 45 31 c9 45 31 c0 31 d2 48 8b 45 00 48 89 44 24 48 31 c0 48 8d 74 24 3c 31 c0 48 89 cf 48 89 74 24 20 31 c9 89 44 24 3c e8 90 00 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}