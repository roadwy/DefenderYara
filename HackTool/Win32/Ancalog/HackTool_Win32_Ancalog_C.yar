
rule HackTool_Win32_Ancalog_C{
	meta:
		description = "HackTool:Win32/Ancalog.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 4c 61 7a 4c 6f 67 67 65 72 } //01 00  TLazLogger
		$a_01_1 = {45 78 70 6c 6f 69 74 20 42 75 69 6c 64 65 72 } //01 00  Exploit Builder
		$a_01_2 = {55 73 65 20 74 68 69 73 20 73 6f 66 74 77 61 72 65 20 6f 6e 6c 79 20 66 6f 72 20 65 64 75 63 61 74 69 6f 6e 61 6c 20 70 75 72 70 6f 73 65 73 20 61 6e 64 20 70 65 6e 65 74 72 61 74 69 6f 6e 20 74 65 73 74 73 2e 20 4e 6f 20 69 6c 6c 65 67 61 6c 20 61 63 74 69 76 69 74 69 65 73 21 } //00 00  Use this software only for educational purposes and penetration tests. No illegal activities!
	condition:
		any of ($a_*)
 
}