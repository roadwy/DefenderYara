
rule Trojan_Win32_AgentTesla_F_{
	meta:
		description = "Trojan:Win32/AgentTesla.F!!AgentTesla.gen!MTB,SIGNATURE_TYPE_ARHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {4d 69 63 72 6f 73 6f 66 74 5c 45 64 67 65 5c 55 73 65 72 20 44 61 74 61 5c 4c 6f 67 69 6e 20 44 61 74 61 } //01 00  Microsoft\Edge\User Data\Login Data
		$a_81_1 = {5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //01 00  \Default\Login Data
		$a_81_2 = {57 69 6e 64 6f 77 73 20 53 65 63 75 72 65 20 4e 6f 74 65 } //01 00  Windows Secure Note
		$a_81_3 = {57 69 6e 64 6f 77 73 20 57 65 62 20 50 61 73 73 77 6f 72 64 20 43 72 65 64 65 6e 74 69 61 6c } //01 00  Windows Web Password Credential
		$a_81_4 = {57 69 6e 64 6f 77 73 20 43 72 65 64 65 6e 74 69 61 6c 20 50 69 63 6b 65 72 20 50 72 6f 74 65 63 74 6f 72 } //01 00  Windows Credential Picker Protector
		$a_81_5 = {57 65 62 20 43 72 65 64 65 6e 74 69 61 6c 73 } //01 00  Web Credentials
		$a_81_6 = {5c 42 6c 61 63 6b 48 61 77 6b 5c 70 72 6f 66 69 6c 65 73 2e 69 6e 69 } //00 00  \BlackHawk\profiles.ini
	condition:
		any of ($a_*)
 
}