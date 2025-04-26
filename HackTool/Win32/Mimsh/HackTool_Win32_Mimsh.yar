
rule HackTool_Win32_Mimsh{
	meta:
		description = "HackTool:Win32/Mimsh,SIGNATURE_TYPE_PEHSTR,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {67 69 74 68 75 62 2e 63 6f 6d 2f 63 6c 79 6d 62 33 72 2f 50 6f 77 65 72 53 68 65 6c 6c 2f 62 6c 6f 62 2f 6d 61 73 74 65 72 2f 49 6e 76 6f 6b 65 2d 4d 69 6d 69 6b 61 74 7a 2f 49 6e 76 6f 6b 65 2d 4d 69 6d 69 6b 61 74 7a 2e 70 73 31 } //1 github.com/clymb3r/PowerShell/blob/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1
		$a_01_1 = {74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 6d 6e 71 38 35 34 65 } //1 tinyurl.com/mnq854e
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=5
 
}