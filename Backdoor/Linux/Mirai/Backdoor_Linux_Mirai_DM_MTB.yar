
rule Backdoor_Linux_Mirai_DM_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.DM!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 39 33 2e 34 32 2e 33 32 2e 31 37 35 } //1 193.42.32.175
		$a_01_1 = {2e 73 68 73 74 72 74 61 62 00 2e 69 6e 69 74 00 2e 74 65 78 74 00 2e 66 69 6e 69 00 2e 72 6f 64 61 74 61 00 2e 63 74 6f 72 73 00 2e 64 74 6f 72 73 00 2e 64 61 74 61 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}