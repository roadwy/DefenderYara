
rule Backdoor_Linux_Mirai_JH_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.JH!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {93 60 1d 40 c1 d1 23 63 1c 01 1c 61 18 33 38 23 09 ?? 33 61 e0 71 b3 62 1d 42 c3 61 3d 41 23 6c 3d 49 1b 2c 3d 4b } //1
		$a_01_1 = {ff e0 8c 52 19 23 8b 51 38 23 2c 31 29 00 11 18 ff 70 12 18 26 4f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}