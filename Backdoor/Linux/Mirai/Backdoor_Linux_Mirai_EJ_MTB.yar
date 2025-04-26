
rule Backdoor_Linux_Mirai_EJ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.EJ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {34 97 69 88 78 c0 68 8a 77 71 34 72 63 6a 00 } //1
		$a_01_1 = {34 83 7e 91 34 9a 69 8e 75 73 74 7a } //1
		$a_01_2 = {2e 73 68 73 74 72 74 61 62 00 2e 69 6e 69 74 00 2e 74 65 78 74 00 2e 66 69 6e 69 00 2e 72 6f 64 61 74 61 00 2e 63 74 6f 72 73 00 2e 64 74 6f 72 73 00 2e 64 61 74 61 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}