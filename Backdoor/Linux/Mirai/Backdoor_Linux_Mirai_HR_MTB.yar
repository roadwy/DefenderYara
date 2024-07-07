
rule Backdoor_Linux_Mirai_HR_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.HR!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff c9 83 f9 ff 74 90 01 01 48 63 d7 0f b6 06 41 3a 04 10 75 90 01 01 ff c7 39 fb 75 90 01 01 66 90 01 01 e9 90 01 04 31 f6 bf 16 00 00 00 90 00 } //1
		$a_03_1 = {48 c7 44 24 38 00 00 00 00 0f 90 01 05 66 c1 cd 08 66 89 6c 24 2a 44 0f b6 6c 24 27 45 85 ed 0f 90 01 05 41 8d 45 ff 48 8b 6c 24 18 45 31 e4 48 ff c0 48 89 44 24 10 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}