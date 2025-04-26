
rule Trojan_BAT_AgentTesla_MX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {16 9a 0a 06 6f ?? ?? ?? ?? 19 9a 0b 07 72 ?? ?? 00 70 17 18 8d ?? ?? ?? ?? 25 17 19 8d ?? ?? ?? ?? 25 16 7e ?? 00 00 04 a2 25 17 7e ?? 00 00 04 a2 25 18 72 ?? ?? 00 70 a2 a2 28 ?? ?? ?? ?? 26 2a } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_MX_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {4c 65 72 6c 69 62 72 6f 5f 49 4e 43 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 Lerlibro_INC.My.Resources
		$a_81_1 = {24 31 31 31 61 64 30 32 62 2d 63 63 63 64 2d 34 31 30 36 2d 62 33 32 38 2d 39 33 62 33 61 64 62 30 35 65 35 32 } //1 $111ad02b-cccd-4106-b328-93b3adb05e52
		$a_81_2 = {42 75 6e 69 66 75 45 6c 69 70 73 65 31 } //1 BunifuElipse1
		$a_81_3 = {70 61 6e 65 6c 4d 49 53 } //1 panelMIS
		$a_81_4 = {6c 76 77 55 73 65 72 73 } //1 lvwUsers
		$a_81_5 = {74 78 74 50 61 73 73 } //1 txtPass
		$a_81_6 = {69 73 50 61 73 73 77 6f 72 64 } //1 isPassword
		$a_81_7 = {62 79 74 65 73 54 6f 44 65 63 6f 6d 70 72 65 73 73 } //1 bytesToDecompress
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}
rule Trojan_BAT_AgentTesla_MX_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 09 00 00 "
		
	strings :
		$a_01_0 = {57 fd a3 ff 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 d7 } //10
		$a_01_1 = {49 43 72 65 64 65 6e 74 69 61 6c 73 } //1 ICredentials
		$a_01_2 = {67 65 74 5f 43 6f 6e 74 72 6f 6c 73 } //1 get_Controls
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
		$a_01_4 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //1 UnhookWindowsHookEx
		$a_01_5 = {44 65 62 75 67 67 65 72 } //1 Debugger
		$a_01_6 = {61 64 64 5f 4d 6f 75 73 65 44 6f 77 6e } //1 add_MouseDown
		$a_01_7 = {53 75 73 70 65 6e 64 54 68 72 65 61 64 } //1 SuspendThread
		$a_01_8 = {73 65 74 5f 50 61 73 73 77 6f 72 64 43 68 61 72 } //1 set_PasswordChar
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=18
 
}