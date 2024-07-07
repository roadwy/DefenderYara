
rule Backdoor_Linux_HShell_A_MTB{
	meta:
		description = "Backdoor:Linux/HShell.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 68 65 72 73 68 65 6c 6c 2f 73 68 65 6c 6c 2e 49 6e 6a 65 63 74 53 68 65 6c 6c 63 6f 64 65 } //1 /hershell/shell.InjectShellcode
		$a_00_1 = {6d 65 74 65 72 70 72 65 74 65 72 2e 52 65 76 65 72 73 65 48 74 74 70 } //1 meterpreter.ReverseHttp
		$a_00_2 = {68 65 72 73 68 65 6c 6c 2d 6d 61 73 74 65 72 2f 6d 65 74 65 72 70 72 65 74 65 72 2f 6d 65 74 65 72 70 72 65 74 65 72 2e 67 6f } //1 hershell-master/meterpreter/meterpreter.go
		$a_00_3 = {73 79 73 64 72 65 61 6d 2f 68 65 72 73 68 65 6c 6c 2f 73 68 65 6c 6c 2e 47 65 74 53 68 65 6c 6c } //1 sysdream/hershell/shell.GetShell
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=2
 
}