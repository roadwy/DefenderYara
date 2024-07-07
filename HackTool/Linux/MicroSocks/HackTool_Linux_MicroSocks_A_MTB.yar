
rule HackTool_Linux_MicroSocks_A_MTB{
	meta:
		description = "HackTool:Linux/MicroSocks.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 89 45 d8 48 8d 95 c0 fd ff ff 48 8b 75 d8 8b 45 fc b9 00 01 00 00 89 c7 e8 90 01 02 ff ff 0f b7 75 e6 48 8b 85 a8 fd ff ff 8b 40 1c 48 8d 8d d0 fe ff ff 48 8d 95 c0 fd ff ff 41 89 f1 49 89 c8 48 89 d1 89 c2 be d8 29 40 00 bf 02 00 00 00 b8 00 00 00 00 90 00 } //1
		$a_03_1 = {0f 95 c0 48 8d 74 83 0c 4c 8d bc 24 a0 08 00 00 b9 00 01 00 00 4c 89 fa e8 90 01 01 f3 ff ff 8b 53 24 48 8d 35 7c 03 00 00 4c 8d 84 24 20 04 00 00 bf 02 00 00 00 31 c0 4c 89 f9 41 89 e9 e8 90 01 01 f2 ff ff 8b 7b 24 90 00 } //1
		$a_03_2 = {48 89 45 f8 48 8d 95 c0 fd ff ff 48 8b 75 f8 8b 7d dc b9 00 01 00 00 e8 90 01 02 ff ff 0f b7 55 f2 48 8b 85 a8 fd ff ff 8b 70 1c 48 8d 85 d0 fe ff ff 48 8d 8d c0 fd ff ff 41 89 d1 49 89 c0 89 f2 be 58 2b 40 00 bf 02 00 00 00 b8 00 00 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}