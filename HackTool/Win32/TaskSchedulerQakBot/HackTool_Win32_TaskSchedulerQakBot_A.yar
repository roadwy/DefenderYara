
rule HackTool_Win32_TaskSchedulerQakBot_A{
	meta:
		description = "HackTool:Win32/TaskSchedulerQakBot.A,SIGNATURE_TYPE_CMDHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 } //01 00  schtasks.exe
		$a_00_1 = {2f 00 63 00 72 00 65 00 61 00 74 00 65 00 } //01 00  /create
		$a_00_2 = {6e 00 74 00 20 00 61 00 75 00 74 00 68 00 6f 00 72 00 69 00 74 00 79 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 } //01 00  nt authority\system
		$a_00_3 = {2f 00 74 00 6e 00 } //01 00  /tn
		$a_00_4 = {2f 00 74 00 72 00 } //01 00  /tr
		$a_00_5 = {2f 00 73 00 63 00 20 00 6f 00 6e 00 63 00 65 00 20 00 2f 00 7a 00 20 00 2f 00 73 00 74 00 } //01 00  /sc once /z /st
		$a_00_6 = {2f 00 65 00 74 00 } //00 00  /et
	condition:
		any of ($a_*)
 
}