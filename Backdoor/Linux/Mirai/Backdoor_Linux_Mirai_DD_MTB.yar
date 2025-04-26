
rule Backdoor_Linux_Mirai_DD_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.DD!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 82 4e 92 72 ff b2 80 67 20 4a 80 66 24 2f 2e 00 08 61 ff 00 00 fc 30 61 ff 00 00 ab d6 48 78 00 09 2f 00 61 ff 00 } //1
		$a_01_1 = {00 73 2f 05 61 ff 00 00 e2 60 2a 48 42 a7 48 78 00 02 2f 02 2f 03 45 f9 80 00 06 00 4e 92 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}