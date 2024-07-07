
rule Backdoor_Linux_Mirai_AV_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.AV!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {66 75 69 72 65 77 68 66 72 65 69 75 72 68 65 68 69 75 67 65 72 68 67 75 69 65 72 75 68 69 72 67 65 75 69 68 72 65 67 69 75 68 72 67 65 } //1 fuirewhfreiurhehiugerhguieruhirgeuihregiuhrge
		$a_00_1 = {72 65 75 39 68 66 67 72 65 79 67 66 72 65 69 75 65 72 68 66 65 72 69 75 6f 6a 66 72 62 68 75 69 66 65 72 62 } //1 reu9hfgreygfreiuerhferiuojfrbhuiferb
		$a_00_2 = {62 79 70 61 73 73 } //1 bypass
		$a_00_3 = {75 64 70 72 61 6e 64 } //1 udprand
		$a_00_4 = {74 63 70 72 61 6e 64 } //1 tcprand
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}