
rule Backdoor_Linux_Mirai_JD_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.JD!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 86 01 68 01 a6 cf 70 20 01 11 00 8a 20 03 17 00 d9 00 da 00 db 56 20 44 23 6f 22 3f 00 8c 20 30 80 c8 f7 fc 1c c8 b7 0a 0a 40 01 04 14 1f 34 } //1
		$a_03_1 = {21 8d 01 6d a5 e1 c0 25 a1 10 ?? ?? 8c 1c 00 30 00 d8 40 c0 52 0d 20 00 55 24 c0 38 62 0c 20 00 55 24 c0 38 a4 14 00 30 4b ?? ?? ?? b2 14 81 30 55 24 c2 3d 16 26 40 70 ff ff f8 ff 18 62 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}