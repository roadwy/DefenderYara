
rule Backdoor_Linux_Mirai_BP_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.BP!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {83 c4 10 85 ff 74 19 31 c0 81 bc 24 a8 01 00 00 ff 64 cd 1d 0f 9f c0 03 84 24 a4 01 00 00 } //1
		$a_00_1 = {75 20 8b 29 89 c8 29 e8 8b 70 08 8b 50 0c 8b 4e 0c 39 c1 75 3d 39 4a 08 75 38 01 ef 89 56 0c 89 72 08 } //1
		$a_03_2 = {7e 20 3a 43 04 74 23 8d 53 08 31 c9 eb ?? 0f b6 42 04 89 d3 83 c2 08 3a 44 24 03 74 0d 41 39 f1 75 ec 8b 44 24 1c } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}