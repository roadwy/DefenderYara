
rule Backdoor_Linux_Mirai_LG_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.LG!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 65 72 76 65 72 3a 20 44 4f 53 61 72 72 65 73 74 } //1 Server: DOSarrest
		$a_01_1 = {74 6d 70 2f 2e 69 6e 73 74 61 6e 63 65 5f 6c 6f 63 6b } //1 tmp/.instance_lock
		$a_01_2 = {66 74 70 67 65 74 20 2d 76 20 2d 75 20 61 6e 6f 6e 79 6d 6f 75 73 } //1 ftpget -v -u anonymous
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}