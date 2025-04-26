
rule Backdoor_Linux_Mirai_HQ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.HQ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_00_0 = {64 42 9f e5 00 00 a0 e3 02 19 a0 e3 7e ff ff eb 01 00 a0 e3 04 10 a0 e1 7b ff ff eb 04 10 a0 e1 02 00 a0 e3 78 ff ff eb 04 00 9d e5 3c 32 9f e5 00 20 90 e5 00 10 9d e5 03 20 81 e7 00 40 90 e5 00 00 54 e3 0d 00 00 0a 24 32 9f e5 03 30 91 e7 00 40 83 e5 2f 10 a0 e3 } //1
		$a_00_1 = {5c 31 9f e5 00 10 9d e5 03 20 91 e7 02 30 a0 e1 00 00 53 e3 03 00 00 0a 0f e0 a0 e1 12 ff 2f e1 00 30 a0 e3 00 30 80 e5 10 00 8d e2 9c 00 00 eb 00 00 50 e3 12 00 00 1a a2 00 00 eb } //4
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*4) >=5
 
}