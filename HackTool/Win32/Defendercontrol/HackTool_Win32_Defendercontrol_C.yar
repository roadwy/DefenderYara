
rule HackTool_Win32_Defendercontrol_C{
	meta:
		description = "HackTool:Win32/Defendercontrol.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_80_0 = {77 77 77 2e 73 6f 72 64 75 6d 2e 6f 72 67 } //www.sordum.org  01 00 
		$a_80_1 = {64 43 6f 6e 74 72 6f 6c 2e 65 78 65 } //dControl.exe  01 00 
		$a_80_2 = {64 66 43 6f 6e 74 72 6f 6c 2e 65 78 65 } //dfControl.exe  00 00 
	condition:
		any of ($a_*)
 
}