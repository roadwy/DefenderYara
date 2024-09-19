
rule Backdoor_Linux_Mirai_IP_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.IP!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {89 c2 83 ee 04 c1 e2 0b 31 c2 44 89 c0 c1 e8 13 89 d1 44 31 c0 c1 e9 08 31 c2 31 d1 89 0f 48 83 c7 04 85 f6 7e 3b 44 89 c8 45 89 d1 45 89 c2 41 89 c8 83 fe 03 7f c9 83 fe 01 74 42 } //1
		$a_00_1 = {80 f9 d4 0f 94 c0 84 44 24 18 74 16 40 80 ff df 0f 97 c2 40 80 ff ff 0f 95 c0 84 d0 0f 85 3d ed ff ff 80 f9 59 0f 94 c0 84 44 24 33 74 16 40 80 ff 5f 0f 97 c2 40 80 ff 60 0f 96 c0 84 d0 0f 85 1b ed ff ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}