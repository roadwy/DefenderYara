
rule HackTool_Win32_Skender{
	meta:
		description = "HackTool:Win32/Skender,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4b 59 50 45 34 43 4f 4d 4c 69 62 } //01 00 
		$a_00_1 = {6b 79 70 65 73 65 6e 64 65 72 2e 72 75 2f } //00 00 
	condition:
		any of ($a_*)
 
}