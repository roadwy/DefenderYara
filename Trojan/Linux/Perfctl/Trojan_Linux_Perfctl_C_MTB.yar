
rule Trojan_Linux_Perfctl_C_MTB{
	meta:
		description = "Trojan:Linux/Perfctl.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e4 c1 e8 04 83 f8 01 74 29 83 f8 01 72 07 83 f8 02 74 49 eb 67 8b 45 f8 23 45 f4 89 c2 8b 45 f8 f7 d0 23 45 f0 09 d0 89 45 ec 8b 45 e4 89 45 e8 eb 69 } //1
		$a_01_1 = {8d 50 01 89 55 fc 8b 4d f8 48 8b 55 a0 48 01 ca 0f b6 0a 48 8b 55 a8 89 c0 88 4c 02 18 8b 45 fc 83 e0 3f 85 c0 0f 85 a6 00 00 00 c7 45 f4 00 00 00 00 eb 79 8b 45 f4 c1 e0 02 8d 50 03 48 8b 45 a8 89 d2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}