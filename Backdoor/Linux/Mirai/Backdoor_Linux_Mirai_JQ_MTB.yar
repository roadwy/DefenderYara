
rule Backdoor_Linux_Mirai_JQ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.JQ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0e 30 4b e5 0d 30 4b e5 0e 20 4b e2 14 30 1b e5 00 30 d3 e5 00 30 c2 e5 0e 30 4b e2 00 20 d3 e5 01 30 d3 e5 03 34 82 e1 1c 10 1b e5 03 10 81 e0 1c 10 0b e5 } //1
		$a_01_1 = {ff 30 03 e2 03 30 61 e0 ff 10 03 e2 3c 20 1b e5 70 31 1b e5 94 03 03 e0 02 30 83 e0 05 20 83 e0 01 30 a0 e1 00 30 c2 e5 34 30 1b e5 01 30 83 e2 34 30 0b e5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}