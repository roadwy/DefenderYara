
rule HackTool_Win32_Ancalog_D{
	meta:
		description = "HackTool:Win32/Ancalog.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 4c 61 7a 4c 6f 67 67 65 72 } //01 00 
		$a_01_1 = {45 78 70 6c 6f 69 74 20 42 75 69 6c 64 65 72 } //01 00 
		$a_01_2 = {2f 46 6f 72 20 70 65 6e 65 74 72 61 74 69 6f 6e 20 74 65 73 74 73 20 6f 6e 6c 79 21 } //00 00 
	condition:
		any of ($a_*)
 
}