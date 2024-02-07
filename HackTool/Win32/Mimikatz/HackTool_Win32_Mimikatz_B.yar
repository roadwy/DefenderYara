
rule HackTool_Win32_Mimikatz_B{
	meta:
		description = "HackTool:Win32/Mimikatz.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 52 00 69 00 6d 00 41 00 72 00 74 00 73 00 5c 00 42 00 32 00 5c 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 } //01 00  Software\RimArts\B2\Settings
		$a_01_1 = {73 00 68 00 69 00 70 00 5c 00 61 00 74 00 6c 00 6d 00 66 00 63 00 5c 00 73 00 72 00 63 00 5c 00 6d 00 66 00 63 00 5c 00 61 00 75 00 78 00 64 00 61 00 74 00 61 00 2e 00 63 00 70 00 70 00 } //01 00  ship\atlmfc\src\mfc\auxdata.cpp
		$a_01_2 = {5c 00 69 00 6e 00 66 00 5c 00 73 00 65 00 74 00 75 00 70 00 61 00 70 00 69 00 2e 00 64 00 65 00 76 00 2e 00 6c 00 6f 00 67 00 } //01 00  \inf\setupapi.dev.log
		$a_01_3 = {53 45 4c 45 43 54 20 69 64 20 46 52 4f 4d 20 6d 6f 7a 5f 68 69 73 74 6f 72 79 76 69 73 69 74 73 20 4f 52 44 45 52 20 42 59 20 69 64 } //00 00  SELECT id FROM moz_historyvisits ORDER BY id
	condition:
		any of ($a_*)
 
}