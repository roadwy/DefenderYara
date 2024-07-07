
rule HackTool_Win32_Vncpwdump_dha{
	meta:
		description = "HackTool:Win32/Vncpwdump!dha,SIGNATURE_TYPE_PEHSTR,64 00 64 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 5c 2e 5c 70 69 70 65 5c 76 6e 63 64 75 6d 70 2d 25 64 } //1 \\.\pipe\vncdump-%d
		$a_01_1 = {76 6e 63 64 75 6d 70 64 6c 6c 2e 64 6c 6c } //1 vncdumpdll.dll
		$a_01_2 = {49 6e 6a 65 63 74 44 6c 6c } //1 InjectDll
		$a_01_3 = {76 6e 63 5f 68 61 78 78 6f 72 } //1 vnc_haxxor
		$a_01_4 = {56 4e 43 50 77 64 75 6d 70 } //1 VNCPwdump
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=100
 
}