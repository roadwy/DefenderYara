
rule Trojan_BAT_AgentTesla_LNP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LNP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 6d 61 72 74 41 73 73 65 6d 62 6c 79 2e 53 6d 61 72 74 45 78 63 65 70 74 69 6f 6e 73 43 6f 72 65 2e 52 65 73 6f 75 72 63 65 73 2e 63 75 72 72 65 6e 74 2e 70 6e 67 } //1 SmartAssembly.SmartExceptionsCore.Resources.current.png
		$a_01_1 = {41 77 65 69 69 77 69 2e 65 78 65 } //1 Aweiiwi.exe
		$a_01_2 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_6 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_7 = {47 65 74 4d 65 74 68 6f 64 73 } //1 GetMethods
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}