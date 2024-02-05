
rule HackTool_Win32_Trilark_A_dha{
	meta:
		description = "HackTool:Win32/Trilark.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 00 00 77 62 00 00 54 68 65 20 66 69 6c 65 20 63 6f 77 62 6f 79 20 69 73 6e 27 74 20 74 68 65 72 65 21 00 00 00 00 72 62 00 00 63 6f 77 62 6f 79 } //00 00 
	condition:
		any of ($a_*)
 
}