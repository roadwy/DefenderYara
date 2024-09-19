
rule Backdoor_Linux_Mirai_JB_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.JB!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {82 07 bf f8 87 31 20 05 84 10 20 01 87 28 e0 02 85 28 80 04 86 00 c0 01 c2 00 ff 5c 82 10 40 02 c2 20 ff 5c 23 00 00 c8 } //1
		$a_03_1 = {c2 4a 3f ff 80 a0 60 0d 02 [0-03] ?? 02 3f ff 80 a0 60 0a 22 [0-03] c0 2a 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}