
rule HackTool_Win32_Defendercontrol_C{
	meta:
		description = "HackTool:Win32/Defendercontrol.C,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_80_0 = {4f 6e 65 43 79 62 65 72 } //OneCyber  65526
		$a_80_1 = {77 77 77 2e 73 6f 72 64 75 6d 2e 6f 72 67 } //www.sordum.org  10
		$a_80_2 = {64 43 6f 6e 74 72 6f 6c 2e 65 78 65 } //dControl.exe  1
		$a_80_3 = {64 66 43 6f 6e 74 72 6f 6c 2e 65 78 65 } //dfControl.exe  1
		$a_80_4 = {41 75 74 6f 49 74 } //AutoIt  1
	condition:
		((#a_80_0  & 1)*65526+(#a_80_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=12
 
}