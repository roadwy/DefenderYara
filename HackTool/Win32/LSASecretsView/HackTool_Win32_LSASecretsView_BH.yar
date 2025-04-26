
rule HackTool_Win32_LSASecretsView_BH{
	meta:
		description = "HackTool:Win32/LSASecretsView.BH,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 6f 6c 69 63 79 5c 50 6f 6c 53 65 63 72 65 74 45 6e 63 72 79 70 74 69 6f 6e 4b 65 79 } //1 Policy\PolSecretEncryptionKey
		$a_01_1 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //1 SeDebugPrivilege
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4e 69 72 53 6f 66 74 5c 4c 53 41 53 65 63 72 65 74 73 56 69 65 77 } //1 Software\NirSoft\LSASecretsView
		$a_01_3 = {5c 50 72 6f 6a 65 63 74 73 5c 56 53 32 30 30 35 5c 4c 53 41 53 65 63 72 65 74 73 56 69 65 77 5c 52 65 6c 65 61 73 65 5c 4c 53 41 53 65 63 72 65 74 73 56 69 65 77 } //1 \Projects\VS2005\LSASecretsView\Release\LSASecretsView
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}