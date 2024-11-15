
rule Trojan_Linux_Perfctl_A_MTB{
	meta:
		description = "Trojan:Linux/Perfctl.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8d 3d 49 0e 21 00 48 8d 05 49 0e 21 00 55 48 29 f8 48 89 e5 48 83 f8 0e 76 15 48 8b 05 ae d9 20 00 48 85 c0 74 09 5d ff e0 66 0f 1f 44 00 00 5d c3 0f 1f 40 00 66 2e 0f 1f 84 00 00 00 00 00 48 8d 3d 09 0e 21 00 48 8d 35 02 0e 21 00 55 48 29 fe 48 89 e5 48 c1 fe 03 } //1
		$a_01_1 = {80 3d b9 0d 21 00 00 75 27 48 83 3d 67 d9 20 00 00 55 48 89 e5 74 0c 48 8b 3d 42 dc 20 00 e8 3d ff ff ff e8 48 ff ff ff 5d c6 05 90 0d 21 00 01 f3 c3 0f 1f 40 00 66 2e 0f 1f 84 00 00 00 00 00 48 8d 3d f1 d6 20 00 48 83 3f 00 75 0b e9 5e ff ff ff 66 0f 1f 44 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}