
rule Backdoor_MacOS_HShell_B_MTB{
	meta:
		description = "Backdoor:MacOS/HShell.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {49 3b 66 10 76 73 48 83 ec 28 48 89 6c 24 20 48 8d 6c 24 20 48 89 44 24 30 48 89 4c 24 40 66 90 48 83 fb 04 75 08 81 38 68 74 74 70 74 14 48 83 fb 05 75 15 81 38 68 74 74 70 75 0d 80 78 04 73 75 07 } //01 00 
		$a_00_1 = {68 65 72 73 68 65 6c 6c 2d 6d 61 73 74 65 72 2f 6d 65 74 65 72 70 72 65 74 65 72 2f 6d 65 74 65 72 70 72 65 74 65 72 2e 67 6f } //01 00  hershell-master/meterpreter/meterpreter.go
		$a_00_2 = {67 69 74 68 75 62 2e 63 6f 6d 2f 73 79 73 64 72 65 61 6d 2f 68 65 72 73 68 65 6c 6c } //01 00  github.com/sysdream/hershell
		$a_00_3 = {73 68 65 6c 6c 2e 49 6e 6a 65 63 74 53 68 65 6c 6c 63 6f 64 65 } //01 00  shell.InjectShellcode
		$a_00_4 = {68 65 72 73 68 65 6c 6c 2f 73 68 65 6c 6c 2e 45 78 65 63 53 68 65 6c 6c 63 6f 64 65 } //01 00  hershell/shell.ExecShellcode
		$a_00_5 = {6d 65 74 65 72 70 72 65 74 65 72 2e 52 65 76 65 72 73 65 54 63 70 } //00 00  meterpreter.ReverseTcp
	condition:
		any of ($a_*)
 
}