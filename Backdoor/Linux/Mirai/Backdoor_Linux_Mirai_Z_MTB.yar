
rule Backdoor_Linux_Mirai_Z_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.Z!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {a0 e1 18 10 1b e5 01 38 a0 e1 23 38 a0 e1 03 20 82 e0 ?? 20 0b e5 18 20 1b e5 22 38 a0 e1 18 10 1b e5 03 10 81 e0 18 10 0b e5 18 20 1b } //1
		$a_00_1 = {e5 1c 30 1b e5 03 00 a0 e1 fc 10 9f e5 51 0b 00 eb 00 30 a0 e1 18 30 0b e5 18 30 1b e5 00 00 53 e3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}