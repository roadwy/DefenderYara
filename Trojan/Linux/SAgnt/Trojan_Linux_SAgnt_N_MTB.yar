
rule Trojan_Linux_SAgnt_N_MTB{
	meta:
		description = "Trojan:Linux/SAgnt.N!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {be 10 37 4b 01 48 81 ee 10 37 4b 01 48 89 f0 48 c1 ee 3f 48 c1 f8 03 48 01 c6 48 d1 fe 74 ?? b8 00 00 00 00 48 85 c0 74 ?? bf 10 37 4b 01 ff e0 } //1
		$a_03_1 = {41 0f 94 c2 48 83 fa 07 75 ?? 44 0f b7 1c 38 66 41 81 fb 61 6c 75 ?? 0f b6 7c 38 02 ?? 40 80 ff 6c 75 ?? 48 8b 3d eb e0 2d 01 31 c0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}