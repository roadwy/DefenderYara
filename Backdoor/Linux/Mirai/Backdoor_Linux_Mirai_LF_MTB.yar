
rule Backdoor_Linux_Mirai_LF_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.LF!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 04 8b 14 24 89 10 c7 40 04 00 00 00 00 8b 54 24 40 8b 43 04 89 02 c7 42 08 02 00 00 00 c7 42 0c 04 00 00 00 8b 44 24 04 eb 2c 8b 54 24 0c 8b 44 24 08 89 02 c7 42 04 00 00 00 00 8b 54 24 40 8b 43 04 89 02 c7 42 08 0a 00 00 00 c7 42 0c 10 00 00 00 8b 44 24 0c } //1
		$a_01_1 = {0f b6 03 0f b6 53 01 c1 e0 08 09 d0 89 45 04 0f b6 43 02 0f b6 53 03 c1 e0 08 09 d0 89 45 08 0f b6 53 04 0f b6 46 01 c1 e2 18 c1 e0 10 0f b6 4e 02 c1 e1 08 09 c2 0f b6 46 03 09 c2 09 d1 89 4d 0c 0f b6 53 08 0f b6 43 09 c1 e2 08 83 c3 0a 09 c2 89 5d 14 89 55 10 8b 44 24 14 83 c4 10 83 c0 0a 89 45 18 39 54 24 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}