
rule Backdoor_Linux_Mirai_FZ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.FZ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {00 80 60 21 24 02 00 05 3c 03 de ec ac a2 00 10 24 02 00 0b 34 63 e6 6d a4 a2 00 0c 24 02 00 01 ac a3 00 14 a4 a2 00 0e 95 83 00 04 95 86 00 02 95 85 00 00 00 60 10 21 00 06 34 00 00 00 18 21 8d 2a 00 10 00 65 18 25 00 c0 38 21 } //1
		$a_00_1 = {80 85 00 00 00 00 00 00 24 a2 ff d0 30 42 00 ff 2c 42 00 0a 10 40 00 0f 00 00 18 21 00 03 10 c0 00 03 18 40 00 62 18 21 24 84 00 01 00 65 18 21 80 85 00 00 00 00 00 00 24 a2 ff d0 30 42 00 ff 2c 42 00 0a 14 40 ff f5 24 63 ff d0 03 e0 00 08 00 60 10 21 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}