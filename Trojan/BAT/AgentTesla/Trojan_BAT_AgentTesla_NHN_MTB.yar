
rule Trojan_BAT_AgentTesla_NHN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,34 00 34 00 09 00 00 "
		
	strings :
		$a_01_0 = {24 39 35 31 30 30 36 61 37 2d 62 30 32 66 2d 34 33 62 30 2d 39 33 31 33 2d 66 39 34 38 66 32 38 61 62 35 66 61 } //10 $951006a7-b02f-43b0-9313-f948f28ab5fa
		$a_01_1 = {53 6d 74 70 43 6c 69 65 6e 74 } //10 SmtpClient
		$a_01_2 = {4e 65 74 77 6f 72 6b 43 72 65 64 65 6e 74 69 61 6c } //10 NetworkCredential
		$a_01_3 = {67 65 74 5f 41 74 74 61 63 68 6d 65 6e 74 73 } //10 get_Attachments
		$a_01_4 = {48 6f 73 74 20 50 72 6f 63 65 73 73 20 66 6f 72 20 57 69 6e 64 6f 77 73 20 53 65 72 76 69 63 65 73 } //10 Host Process for Windows Services
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_7 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_01_8 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=52
 
}