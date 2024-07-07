
rule Trojan_BAT_AgentTesla_NYJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NYJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 06 5d 0d 03 11 04 9a 0b 03 11 04 03 09 9a a2 03 09 07 a2 00 11 04 17 58 13 04 11 04 06 fe 02 16 fe 01 13 05 11 05 2d d1 } //1
		$a_01_1 = {1f a2 0b 09 03 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 a8 00 00 00 33 00 00 00 4c 01 00 00 79 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_NYJ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NYJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {66 66 66 66 66 66 66 64 68 73 64 68 73 64 68 73 68 64 66 68 66 73 64 66 66 66 66 66 66 } //1 fffffffdhsdhsdhshdfhfsdffffff
		$a_81_1 = {66 66 61 73 73 66 73 64 64 68 73 64 66 68 64 66 66 73 64 66 66 } //1 ffassfsddhsdfhdffsdff
		$a_81_2 = {66 61 66 66 66 66 67 66 66 66 66 66 66 20 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 } //1 faffffgffffff ssssssssssssssss
		$a_81_3 = {61 64 73 73 73 73 73 73 73 73 73 73 73 61 } //1 adsssssssssssa
		$a_81_4 = {43 3a 5c 4e 65 77 68 54 65 6d 70 } //1 C:\NewhTemp
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_BAT_AgentTesla_NYJ_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NYJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {20 cf 8e fb 0e 13 1a 11 1a 20 0d 8f fb 0e fe 02 13 54 11 54 2c 09 20 cf 8e fb 0e 13 1a 2b 1d 11 1a 20 10 8f fb 0e fe 02 16 fe 01 13 55 11 55 2c 08 11 1a 17 58 13 1a 2b 03 16 13 1a 20 dc 8e fb 0e 13 1b 11 1b 20 c0 8e fb 0e fe 02 13 56 11 56 } //1
		$a_81_1 = {43 6f 6d 70 69 6c 61 74 69 6f 6e 52 65 6c 61 78 61 74 69 6f 6e 73 } //1 CompilationRelaxations
		$a_81_2 = {43 61 74 65 67 6f 72 79 4d 65 6d 62 65 72 73 68 69 70 } //1 CategoryMembership
		$a_81_3 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //1 CompressionMode
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}