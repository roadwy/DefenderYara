
rule Trojan_Linux_Turla_XO{
	meta:
		description = "Trojan:Linux/Turla.XO,SIGNATURE_TYPE_ELFHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 ea 03 83 e7 07 c1 e2 0d 90 01 05 8d 41 05 32 06 48 ff c6 88 81 90 01 04 48 ff c1 48 83 f9 49 75 e9 90 00 } //10
		$a_01_1 = {53 48 8d 82 74 38 00 00 4c 8d 82 6c 38 00 00 89 fb 48 89 f7 48 83 ec 10 85 c9 48 8d 8a 24 28 00 00 4c 8d 4c 24 0c 4c 0f 45 c0 48 63 d3 c7 44 24 0c 00 00 00 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}