
rule Trojan_Linux_Perfctl_D_MTB{
	meta:
		description = "Trojan:Linux/Perfctl.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8d 3d 79 32 00 00 48 8d 35 72 32 00 00 48 29 fe 48 89 f0 48 c1 ee 3f 48 c1 f8 03 48 01 c6 48 d1 fe 74 14 48 8b 05 d5 2d 00 00 48 85 c0 74 08 ff e0 } //1
		$a_01_1 = {55 48 89 e5 48 81 ec 30 01 00 00 48 89 bd d8 fe ff ff 48 8d 95 70 ff ff ff 48 8b 85 d8 fe ff ff 48 89 d6 48 89 c7 e8 8a 08 00 00 85 c0 79 0a b8 ff ff ff ff e9 8c 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}