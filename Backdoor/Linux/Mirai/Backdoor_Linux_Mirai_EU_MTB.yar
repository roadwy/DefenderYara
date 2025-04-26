
rule Backdoor_Linux_Mirai_EU_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.EU!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {4b ff fe 6d 3d 60 10 02 3d 20 00 00 80 0b e0 10 39 29 00 00 38 6b e0 10 2f 80 00 00 41 ?? ?? ?? 2f 89 00 00 41 9e 00 0c 7d ?? ?? ?? 4e 80 04 21 80 01 00 14 38 21 00 10 7c 08 03 a6 4e 80 00 20 } //1
		$a_03_1 = {80 09 00 00 38 89 00 04 2f 80 00 00 40 ?? ?? ?? 7c 9d 23 78 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}