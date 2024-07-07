
rule Trojan_BAT_AgentTesla_AMZZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {6c 70 66 73 64 66 41 66 64 73 64 64 73 61 64 72 65 73 73 } //1 lpfsdfAfdsddsadress
		$a_81_1 = {64 77 53 66 73 64 73 61 64 64 73 68 69 7a 65 } //1 dwSfsdsaddshize
		$a_81_2 = {68 50 66 64 73 66 68 64 73 64 72 6f 64 73 63 65 73 73 } //1 hPfdsfhdsdrodscess
		$a_81_3 = {6c 70 42 61 73 66 73 64 73 64 66 65 64 64 66 68 73 41 64 64 72 65 73 73 } //1 lpBasfsdsdfeddfhsAddress
		$a_81_4 = {6c 70 42 66 64 73 64 68 73 64 73 64 73 66 75 66 66 65 72 } //1 lpBfdsdhsdsdsfuffer
		$a_81_5 = {74 68 72 68 66 64 73 64 73 66 73 64 66 65 61 64 } //1 thrhfdsdsfsdfead
		$a_81_6 = {68 54 68 72 65 68 66 64 66 73 73 64 64 66 61 64 } //1 hThrehfdfssddfad
		$a_81_7 = {68 54 6f 6b 64 73 65 68 66 64 66 73 73 64 66 6e } //1 hTokdsehfdfssdfn
		$a_81_8 = {6c 70 41 70 70 6c 69 63 61 74 68 66 73 64 66 73 64 73 69 6f 6e 4e 61 6d 65 } //1 lpApplicathfsdfsdsionName
		$a_81_9 = {6c 70 50 72 6f 63 64 65 73 64 68 73 41 74 74 64 73 64 66 73 64 66 72 69 62 75 74 65 73 } //1 lpProcdesdhsAttdsdfsdfributes
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}