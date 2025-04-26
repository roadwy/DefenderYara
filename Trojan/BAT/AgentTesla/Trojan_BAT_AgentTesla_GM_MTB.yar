
rule Trojan_BAT_AgentTesla_GM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {44 41 4c 5f 44 6f 77 6e 6c 6f 61 64 5f 4c 69 73 74 5f 47 65 6e 65 72 61 74 6f 72 } //1 DAL_Download_List_Generator
		$a_81_1 = {41 63 74 69 76 69 74 79 20 4c 6f 67 67 65 72 } //1 Activity Logger
		$a_81_2 = {4d 61 69 6e 5f 53 63 72 65 65 6e } //1 Main_Screen
		$a_81_3 = {50 6f 73 69 74 69 6f 6e } //1 Position
		$a_81_4 = {4c 65 6e 67 74 68 } //1 Length
		$a_81_5 = {69 6d 69 6d 69 6d 69 6d 69 6d } //1 imimimimim
		$a_81_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_7 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}