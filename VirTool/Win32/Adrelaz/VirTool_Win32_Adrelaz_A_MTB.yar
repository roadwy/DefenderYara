
rule VirTool_Win32_Adrelaz_A_MTB{
	meta:
		description = "VirTool:Win32/Adrelaz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {41 44 46 53 52 65 6c 61 79 2f 70 6b 67 2f 6e 74 6c 6d 2e 44 65 63 6f 64 65 4d 65 73 73 61 67 65 } //1 ADFSRelay/pkg/ntlm.DecodeMessage
		$a_81_1 = {73 70 65 77 2f 62 79 70 61 73 73 2e 67 6f } //1 spew/bypass.go
		$a_81_2 = {70 72 61 65 74 6f 72 69 61 6e 2d 69 6e 2f 41 44 46 53 52 65 6c 61 79 2f 70 6b 67 2f 63 6f 6f 6b 69 65 73 } //1 praetorian-in/ADFSRelay/pkg/cookies
		$a_81_3 = {41 44 46 53 52 65 6c 61 79 2f 70 6b 67 2f 6e 74 6c 6d 2f 6e 74 6c 6d 2e 67 6f } //1 ADFSRelay/pkg/ntlm/ntlm.go
		$a_81_4 = {41 44 46 53 52 65 6c 61 79 2f 41 44 46 53 52 65 6c 61 79 2e 67 6f } //1 ADFSRelay/ADFSRelay.go
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}