
rule HackTool_Win32_UACBypass_A{
	meta:
		description = "HackTool:Win32/UACBypass.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 00 65 00 6c 00 65 00 67 00 61 00 74 00 65 00 45 00 78 00 65 00 63 00 75 00 74 00 65 00 } //1 DelegateExecute
		$a_01_1 = {43 00 6c 00 61 00 73 00 73 00 65 00 73 00 5c 00 6d 00 73 00 2d 00 73 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //1 Classes\ms-settings\shell\open\command
		$a_01_2 = {55 00 41 00 43 00 5f 00 42 00 79 00 70 00 61 00 73 00 73 00 } //1 UAC_Bypass
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}