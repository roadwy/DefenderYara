
rule Trojan_Win32_VB_AGT{
	meta:
		description = "Trojan:Win32/VB.AGT,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 68 69 73 69 73 73 76 63 68 6f 73 74 } //3 thisissvchost
		$a_01_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 63 00 6f 00 70 00 79 00 20 00 2f 00 79 00 20 00 22 00 } //2 cmd.exe /c copy /y "
		$a_01_2 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}