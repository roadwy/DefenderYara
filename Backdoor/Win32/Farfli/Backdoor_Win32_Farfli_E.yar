
rule Backdoor_Win32_Farfli_E{
	meta:
		description = "Backdoor:Win32/Farfli.E,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {61 74 74 72 69 62 20 22 43 3a 5c 6d 79 61 70 70 2e 65 78 65 22 20 2d 72 20 2d 61 20 2d 73 20 2d 68 } //1 attrib "C:\myapp.exe" -r -a -s -h
		$a_01_1 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
		$a_01_2 = {33 36 30 54 72 61 59 2e 65 78 65 } //1 360TraY.exe
		$a_01_3 = {53 65 52 65 73 74 6f 72 65 50 72 69 76 69 6c 65 67 65 } //1 SeRestorePrivilege
		$a_01_4 = {73 6f 75 6c 2a 65 78 65 } //1 soul*exe
		$a_01_5 = {73 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 52 45 52 5c 53 68 65 6c 6c 65 78 65 63 75 74 65 48 6f 6f 6b 73 } //1 software\Microsoft\Windows\CurrentVersion\exploRER\ShellexecuteHooks
		$a_01_6 = {52 61 76 6d 6f 6e 64 2e 65 78 65 00 61 76 70 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}