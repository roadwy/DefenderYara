
rule HackTool_Win32_SharpZeroLogon{
	meta:
		description = "HackTool:Win32/SharpZeroLogon,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 12 00 00 "
		
	strings :
		$a_80_0 = {53 68 61 72 70 5a 65 72 6f 4c 6f 67 6f 6e } //SharpZeroLogon  8
		$a_80_1 = {33 31 64 36 63 66 65 30 64 31 36 61 65 39 33 31 62 37 33 63 35 39 64 37 65 30 63 30 38 39 63 30 } //31d6cfe0d16ae931b73c59d7e0c089c0  2
		$a_01_2 = {b8 01 00 00 00 83 f8 01 75 3b } //1
		$a_80_3 = {6c 6f 67 6f 6e 63 6c 69 2e 64 6c 6c } //logoncli.dll  1
		$a_80_4 = {6e 65 74 61 70 69 33 32 2e 64 6c 6c } //netapi32.dll  1
		$a_81_5 = {49 5f 4e 65 74 53 65 72 76 65 72 52 65 71 43 68 61 6c 6c 65 6e 67 65 } //1 I_NetServerReqChallenge
		$a_81_6 = {49 5f 4e 65 74 53 65 72 76 65 72 41 75 74 68 65 6e 74 69 63 61 74 65 32 } //1 I_NetServerAuthenticate2
		$a_81_7 = {49 5f 4e 65 74 53 65 72 76 65 72 50 61 73 73 77 6f 72 64 53 65 74 32 } //1 I_NetServerPasswordSet2
		$a_81_8 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_81_9 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 ReadProcessMemory
		$a_81_10 = {47 65 74 4d 6f 64 75 6c 65 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 GetModuleInformation
		$a_81_11 = {4e 4c 5f 54 52 55 53 54 5f 50 41 53 53 57 4f 52 44 } //1 NL_TRUST_PASSWORD
		$a_81_12 = {4e 45 54 4c 4f 47 4f 4e 5f 41 55 54 48 45 4e 54 49 43 41 54 4f 52 } //1 NETLOGON_AUTHENTICATOR
		$a_81_13 = {43 6c 65 61 72 4e 65 77 50 61 73 73 77 6f 72 64 } //1 ClearNewPassword
		$a_81_14 = {4e 45 54 4c 4f 47 4f 4e 5f 53 45 43 55 52 45 5f 43 48 41 4e 4e 45 4c 5f 54 59 50 45 } //1 NETLOGON_SECURE_CHANNEL_TYPE
		$a_81_15 = {4e 45 54 4c 4f 47 4f 4e 5f 43 52 45 44 45 4e 54 49 41 4c } //1 NETLOGON_CREDENTIAL
		$a_81_16 = {43 6c 69 65 6e 74 43 68 61 6c 6c 65 6e 67 65 } //1 ClientChallenge
		$a_81_17 = {53 65 72 76 65 72 43 68 61 6c 6c 65 6e 67 65 } //1 ServerChallenge
	condition:
		((#a_80_0  & 1)*8+(#a_80_1  & 1)*2+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1+(#a_81_16  & 1)*1+(#a_81_17  & 1)*1) >=16
 
}