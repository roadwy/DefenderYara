
rule Trojan_BAT_AgentTesla_JUP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JUP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_81_0 = {6e 00 61 00 6d 00 65 00 27 00 3a 00 20 00 27 00 41 00 64 00 6d 00 69 00 6e 00 27 00 20 00 7d 00 7b 00 20 00 27 00 6e 00 61 00 6d 00 65 00 27 00 3a 00 20 00 27 00 50 00 75 00 62 00 6c 00 69 00 73 00 68 00 65 00 72 } //1
		$a_81_1 = {53 00 74 00 61 00 72 00 74 00 2d 00 53 00 6c 00 65 00 65 00 70 00 20 00 2d 00 73 00 20 00 35 00 } //1 Start-Sleep -s 5
		$a_81_2 = {57 61 69 74 46 6f 72 45 78 69 74 } //1 WaitForExit
		$a_81_3 = {54 65 73 74 } //1 Test
		$a_81_4 = {70 6f 77 65 72 73 68 65 6c 6c } //1 powershell
		$a_81_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_6 = {47 65 74 53 74 72 69 6e 67 } //1 GetString
		$a_81_7 = {53 68 6f 77 57 69 6e 64 6f 77 } //1 ShowWindow
		$a_81_8 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_9 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //1 GetCurrentProcess
		$a_81_10 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=11
 
}