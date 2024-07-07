
rule HackTool_Win32_PsCredinject_A_{
	meta:
		description = "HackTool:Win32/PsCredinject.A!!PsCredinject.A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {45 72 72 6f 72 20 63 61 6c 6c 69 6e 67 20 4c 73 61 4c 6f 67 6f 6e 55 73 65 72 2e 20 45 72 72 6f 72 20 63 6f 64 65 3a } //1 Error calling LsaLogonUser. Error code:
		$a_01_1 = {49 6e 76 6f 6b 65 2d 43 72 65 64 65 6e 74 69 61 6c 49 6e 6a 65 63 74 69 6f 6e } //1 Invoke-CredentialInjection
		$a_01_2 = {43 61 6c 6c 20 74 6f 20 4c 73 61 4c 6f 6f 6b 75 70 41 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 50 61 63 6b 61 67 65 20 66 61 69 6c 65 64 2e 20 45 72 72 6f 72 } //1 Call to LsaLookupAuthenticationPackage failed. Error
		$a_01_3 = {45 72 72 6f 72 20 63 61 6c 6c 69 6e 67 20 4c 73 61 43 6f 6e 6e 65 63 74 55 6e 74 72 75 73 74 65 64 2e 20 45 72 72 6f 72 20 63 6f 64 65 } //1 Error calling LsaConnectUntrusted. Error code
		$a_01_4 = {4c 6f 67 6f 6e 20 73 75 63 63 65 65 64 65 64 2c 20 69 6d 70 65 72 73 6f 6e 61 74 69 6e 67 20 74 68 65 20 74 6f 6b 65 6e 20 73 6f 20 69 74 20 63 61 6e 20 62 65 20 6b 69 64 6e 61 70 70 65 64 20 61 6e 64 20 73 74 61 72 74 69 6e 67 20 61 6e 20 69 6e 66 69 6e 69 74 65 20 6c 6f 6f 70 20 77 69 74 68 20 74 68 65 20 74 68 72 65 61 64 } //1 Logon succeeded, impersonating the token so it can be kidnapped and starting an infinite loop with the thread
		$a_00_5 = {5c 00 5c 00 2e 00 5c 00 70 00 69 00 70 00 65 00 5c 00 73 00 71 00 73 00 76 00 63 00 } //1 \\.\pipe\sqsvc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}