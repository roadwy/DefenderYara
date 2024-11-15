
rule Trojan_Linux_Perfctl_B_MTB{
	meta:
		description = "Trojan:Linux/Perfctl.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8d 3d f9 33 00 00 48 8d 35 f2 33 00 00 48 29 fe 48 89 f0 48 c1 ee 3f 48 c1 f8 03 48 01 c6 48 d1 fe 74 14 48 8b 05 d5 2d 00 00 48 85 c0 74 08 ff e0 } //1
		$a_01_1 = {80 3d f1 33 00 00 00 75 2f 55 48 83 3d b6 2d 00 00 00 48 89 e5 74 0c 48 8b 3d 7a 2e 00 00 e8 2d ff ff ff e8 68 ff ff ff c6 05 c9 33 00 00 01 5d c3 0f 1f 80 00 00 00 00 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}