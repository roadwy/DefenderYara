
rule Trojan_BAT_AgentTesla_JTM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 61 2e 75 67 75 75 2e 73 65 2f } //1 https://a.uguu.se/
		$a_81_1 = {68 74 74 70 3a 2f 2f 63 65 79 6c 61 6e 74 72 65 79 6c 65 72 2e 63 6f 6d 2f 43 6d 73 5f 44 61 74 61 2f 53 69 74 65 73 2f 61 73 64 2f 54 68 65 6d 65 73 2f 44 65 66 61 75 6c 74 2f } //1 http://ceylantreyler.com/Cms_Data/Sites/asd/Themes/Default/
		$a_81_2 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_81_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_81_5 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_6 = {74 65 73 74 65 72 2e 72 61 73 61 } //1 tester.rasa
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}