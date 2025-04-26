
rule Backdoor_Linux_Mirai_IR_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.IR!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 53 83 ec 04 bb 00 40 05 08 a1 00 40 05 08 83 f8 ff 74 ?? 83 eb 04 ff d0 8b 03 83 f8 ff 75 ?? 58 5b 5d } //1
		$a_03_1 = {8b 4c 24 0c 8b 5c 24 10 31 c0 8b 35 98 42 05 08 39 d9 74 ?? 0f b6 01 0f bf 14 46 0f b6 03 0f bf 04 46 29 c2 89 d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}