
rule Trojan_Win32_ExecutionViaPowershell_A{
	meta:
		description = "Trojan:Win32/ExecutionViaPowershell.A,SIGNATURE_TYPE_CMDHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 00 65 00 74 00 2d 00 4d 00 70 00 50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 } //1 Set-MpPreference
		$a_00_1 = {47 00 65 00 74 00 2d 00 4d 00 70 00 50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 } //1 Get-MpPreference
		$a_00_2 = {47 00 65 00 74 00 2d 00 4d 00 70 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 53 00 74 00 61 00 74 00 75 00 73 00 } //1 Get-MpComputerStatus
		$a_00_3 = {47 00 65 00 74 00 2d 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 } //1 Get-Process
		$a_00_4 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //6 powershell
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*6) >=7
 
}