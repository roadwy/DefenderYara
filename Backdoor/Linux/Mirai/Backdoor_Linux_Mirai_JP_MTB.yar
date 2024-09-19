
rule Backdoor_Linux_Mirai_JP_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.JP!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 7f 00 10 80 1f 00 18 81 3f 00 3c 7f 8b 00 40 39 29 00 01 91 3f 00 3c 40 ?? ?? ?? 8b cb 00 00 38 0b 00 01 ?? 1f 00 10 } //1
		$a_03_1 = {39 24 ff fe 55 29 f8 7e 39 29 00 01 7d 29 03 a6 39 20 00 00 a0 03 00 00 38 84 ff fe 38 63 00 02 7d 29 02 14 42 ?? ?? ?? 2f 84 00 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}