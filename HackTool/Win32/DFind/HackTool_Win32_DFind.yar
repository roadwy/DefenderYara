
rule HackTool_Win32_DFind{
	meta:
		description = "HackTool:Win32/DFind,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 02 00 "
		
	strings :
		$a_03_0 = {83 f8 52 0f 90 01 03 00 00 0f be 90 01 03 ff ff 83 f8 46 90 00 } //01 00 
		$a_03_1 = {ff ff 28 7c 20 0f be 90 01 03 ff ff 90 00 } //01 00 
		$a_00_2 = {6f 70 65 6e 3a 25 64 20 76 6e 63 3a 25 64 20 70 61 73 73 77 64 3a 25 64 } //01 00  open:%d vnc:%d passwd:%d
		$a_01_3 = {47 45 54 20 2f 77 30 30 74 77 30 30 74 } //01 00  GET /w00tw00t
		$a_00_4 = {43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 42 50 } //01 00  CACACACACACACACACACACACACACACABP
		$a_00_5 = {5c 5c 25 73 5c 69 70 63 24 } //01 00  \\%s\ipc$
		$a_00_6 = {26 6e 65 74 62 69 6f 73 6e 61 6d 65 3a 25 73 } //00 00  &netbiosname:%s
	condition:
		any of ($a_*)
 
}