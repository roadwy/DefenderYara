
rule VirTool_Win32_Kackperk_A_MTB{
	meta:
		description = "VirTool:Win32/Kackperk.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {53 53 48 5f 52 65 76 53 68 65 6c 6c 2f 63 6c 69 65 6e 74 2f 63 6c 69 65 6e 74 2e 67 6f } //1 SSH_RevShell/client/client.go
		$a_81_1 = {53 53 48 5f 52 65 76 53 68 65 6c 6c 2f 63 6c 69 65 6e 74 2f 63 6f 72 65 2f 73 68 65 6c 6c 2e 67 6f } //1 SSH_RevShell/client/core/shell.go
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}