
rule Backdoor_Linux_Mirai_W_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.W!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 85 ff 74 ?? 80 3f 00 74 ?? 48 89 fa 66 66 ?? 0f b6 42 01 48 ff c2 84 c0 75 ?? 89 d1 29 f9 48 85 f6 74 ?? 80 3e 00 74 ?? 48 89 f2 66 66 66 ?? 0f b6 42 01 48 ff c2 84 c0 75 ?? 89 d0 29 f0 39 c1 89 c2 } //1
		$a_03_1 = {43 30 86 8c 14 05 08 83 ec 0c 57 e8 ?? ?? 00 00 83 c4 10 39 d8 77 e6 83 ec 0c 46 55 e8 ?? ?? 00 00 83 c4 10 39 f0 77 d1 83 c4 0c } //1
		$a_03_2 = {85 c0 75 e9 bf ?? ?? 40 00 e8 ?? ?? 00 00 8b 05 ?? ?? 10 00 3d 67 01 00 00 0f 9f c2 ff c0 89 05 ?? ?? 10 00 84 d2 74 ?? b8 00 00 00 00 e8 12 02 00 00 8b 05 ?? ?? 10 00 8d 14 00 8d 04 95 00 00 00 00 8d 04 02 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}