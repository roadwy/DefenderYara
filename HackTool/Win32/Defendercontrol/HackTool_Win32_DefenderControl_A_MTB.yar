
rule HackTool_Win32_DefenderControl_A_MTB{
	meta:
		description = "HackTool:Win32/DefenderControl.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 2e 00 65 00 78 00 65 00 } //01 00  DefenderControl.exe
		$a_01_1 = {54 00 75 00 72 00 6e 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 20 00 6f 00 66 00 66 00 20 00 6f 00 72 00 20 00 6f 00 6e 00 20 00 77 00 69 00 74 00 68 00 20 00 61 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 20 00 72 00 69 00 67 00 68 00 74 00 73 00 } //01 00  Turn Windows Defender off or on with administrator rights
		$a_01_2 = {57 00 69 00 6e 00 44 00 65 00 74 00 65 00 63 00 74 00 48 00 69 00 64 00 64 00 65 00 6e 00 54 00 65 00 78 00 74 00 } //01 00  WinDetectHiddenText
		$a_01_3 = {41 55 33 5f 47 65 74 50 6c 75 67 69 6e 44 65 74 61 69 6c 73 } //00 00  AU3_GetPluginDetails
	condition:
		any of ($a_*)
 
}