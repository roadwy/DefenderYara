
rule Backdoor_Linux_Mirai_GZ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.GZ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {05 00 1c 3c 48 84 9c 27 21 e0 99 03 d0 ff bd 27 28 00 bf af 10 00 bc af 5c 80 99 8f 18 00 a4 af 1c 00 a5 af 20 00 a6 af 06 10 04 24 18 00 a6 27 09 f8 20 03 01 00 05 24 10 00 bc 8f 28 00 bf 8f 00 00 00 00 08 00 e0 03 30 00 bd 27 } //1
		$a_01_1 = {ff 00 a5 30 00 2c 05 00 00 26 04 00 25 20 85 00 ff 00 e7 30 ff 00 c6 30 25 20 87 00 00 32 06 00 25 30 c4 00 02 22 06 00 00 ff c3 30 00 1a 03 00 00 ff 84 30 00 16 06 00 02 36 06 00 25 10 43 00 25 30 c4 00 08 00 e0 03 25 10 46 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}