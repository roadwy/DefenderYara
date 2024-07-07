
rule Backdoor_Linux_Mirai_EM_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.EM!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {7c 1c e8 ae 2f 80 00 3d 41 9e 01 40 39 7d 00 01 91 61 00 08 7f 83 e3 78 48 00 b7 4d 83 a1 00 08 7f 83 e8 00 41 9d ff dc } //1
		$a_00_1 = {41 9e 00 20 7f 63 db 78 7f 84 e3 78 7e 45 93 78 38 c0 00 01 48 00 b4 15 7c 63 f2 14 9b e3 08 44 7f 63 db 78 } //1
		$a_00_2 = {93 bf 00 00 7e a4 ab 78 38 a0 28 00 38 c0 40 00 80 7e 00 00 48 01 0a 71 2c 03 00 00 41 82 02 fc 2f 83 ff ff 40 9e ff dc } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}