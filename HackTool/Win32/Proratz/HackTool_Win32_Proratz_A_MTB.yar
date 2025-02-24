
rule HackTool_Win32_Proratz_A_MTB{
	meta:
		description = "HackTool:Win32/Proratz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {50 72 6f 52 61 74 } //1 ProRat
		$a_81_1 = {43 79 61 6e 20 44 75 73 6b } //1 Cyan Dusk
		$a_81_2 = {53 79 73 74 65 6d 2e 4e 65 74 2e 55 52 4c 43 6c 69 65 6e 74 2e 54 43 72 65 64 65 6e 74 69 61 6c 73 53 74 6f 72 61 67 65 2e 54 43 72 65 64 65 6e 74 69 61 6c } //1 System.Net.URLClient.TCredentialsStorage.TCredential
		$a_81_3 = {53 79 73 74 65 6d 2e 4e 65 74 2e 55 52 4c 43 6c 69 65 6e 74 } //1 System.Net.URLClient
		$a_81_4 = {53 65 72 76 65 72 53 6f 63 6b 65 74 36 } //1 ServerSocket6
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}