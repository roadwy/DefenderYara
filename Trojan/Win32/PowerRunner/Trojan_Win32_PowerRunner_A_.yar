
rule Trojan_Win32_PowerRunner_A_{
	meta:
		description = "Trojan:Win32/PowerRunner.A!!PowerRunner.A,SIGNATURE_TYPE_ARHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_00_0 = {70 72 6f 6a 65 63 74 73 5c 75 6e 6d 61 6e 61 67 65 64 70 6f 77 65 72 73 68 65 6c 6c 5c 70 6f 77 65 72 73 68 65 6c 6c 72 75 6e 6e 65 72 5c } //10 projects\unmanagedpowershell\powershellrunner\
		$a_00_1 = {3c 4d 6f 64 75 6c 65 3e 00 50 6f 77 65 72 53 68 65 6c 6c 52 75 6e 6e 65 72 2e 64 6c 6c 00 50 6f 77 65 72 53 68 65 6c 6c 52 75 6e 6e 65 72 00 43 75 73 74 6f 6d 50 53 48 6f 73 74 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10) >=10
 
}