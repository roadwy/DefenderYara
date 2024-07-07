
rule Trojan_BAT_AgentTesla_HU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.HU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {42 6f 6f 74 73 54 72 61 70 70 65 72 } //1 BootsTrapper
		$a_81_1 = {42 6f 72 6c 61 6e 64 5f 50 72 6f 74 65 63 74 6f 72 20 43 72 61 63 6b 65 64 20 76 31 2e 30 } //1 Borland_Protector Cracked v1.0
		$a_81_2 = {42 61 62 65 6c 4f 62 66 75 73 63 61 74 6f 72 41 74 74 72 69 62 75 74 65 } //1 BabelObfuscatorAttribute
		$a_81_3 = {49 73 4c 6f 67 67 69 6e 67 } //1 IsLogging
		$a_81_4 = {67 65 74 5f 49 73 41 6c 69 76 65 } //1 get_IsAlive
		$a_81_5 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_81_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_7 = {53 6c 65 65 70 } //1 Sleep
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}
rule Trojan_BAT_AgentTesla_HU_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.HU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {57 70 66 50 64 66 55 6e 62 6c 6f 63 6b 65 72 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 WpfPdfUnblocker.My.Resources
		$a_81_1 = {2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f } //1 //cdn.discordapp.com/attachments/
		$a_81_2 = {2f 2f 67 69 74 68 75 62 2e 63 6f 6d 2f } //1 //github.com/
		$a_81_3 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_5 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_6 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_7 = {43 6f 6e 76 65 72 74 } //1 Convert
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}