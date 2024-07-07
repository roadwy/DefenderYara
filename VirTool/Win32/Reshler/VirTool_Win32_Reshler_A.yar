
rule VirTool_Win32_Reshler_A{
	meta:
		description = "VirTool:Win32/Reshler.A,SIGNATURE_TYPE_PEHSTR,07 00 07 00 09 00 00 "
		
	strings :
		$a_01_0 = {2f 68 65 72 73 68 65 6c 6c 2f 73 68 65 6c 6c 2e 45 78 65 63 75 74 65 43 6d 64 } //1 /hershell/shell.ExecuteCmd
		$a_01_1 = {2f 68 65 72 73 68 65 6c 6c 2f 73 68 65 6c 6c 2e 47 65 74 53 68 65 6c 6c } //1 /hershell/shell.GetShell
		$a_01_2 = {2f 68 65 72 73 68 65 6c 6c 2f 6d 65 74 65 72 70 72 65 74 65 72 } //1 /hershell/meterpreter
		$a_01_3 = {2f 73 68 65 6c 6c 2e 49 6e 6a 65 63 74 53 68 65 6c 6c 63 6f 64 65 } //1 /shell.InjectShellcode
		$a_01_4 = {2f 73 68 65 6c 6c 2e 45 78 65 63 53 68 65 6c 6c 63 6f 64 65 } //1 /shell.ExecShellcode
		$a_01_5 = {2f 6d 65 74 65 72 70 72 65 74 65 72 2e 67 65 6e 65 72 61 74 65 55 52 49 43 68 65 63 6b 73 75 6d } //1 /meterpreter.generateURIChecksum
		$a_01_6 = {2f 6d 65 74 65 72 70 72 65 74 65 72 2e 72 65 76 65 72 73 65 54 43 50 } //1 /meterpreter.reverseTCP
		$a_01_7 = {2f 6d 65 74 65 72 70 72 65 74 65 72 2e 72 65 76 65 72 73 65 48 54 54 50 } //1 /meterpreter.reverseHTTP
		$a_01_8 = {2f 73 68 65 6c 6c 2f 73 68 65 6c 6c 5f 77 69 6e 64 6f 77 73 } //1 /shell/shell_windows
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=7
 
}