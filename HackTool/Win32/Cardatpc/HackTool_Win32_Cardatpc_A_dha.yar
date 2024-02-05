
rule HackTool_Win32_Cardatpc_A_dha{
	meta:
		description = "HackTool:Win32/Cardatpc.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 2d 65 73 74 61 62 6c 69 73 68 6e 75 6c 6c 73 65 73 73 69 6f 6e } //01 00 
		$a_01_1 = {2d 2d 74 65 73 74 34 34 35 00 } //01 00 
		$a_01_2 = {63 6c 65 61 6e 6c 61 73 74 2d 64 65 73 63 20 3c 77 6f 72 64 3e 3a } //01 00 
		$a_01_3 = {2d 2d 66 6f 72 63 65 6c 6f 61 64 00 } //00 00 
		$a_00_4 = {5d 04 00 } //00 ba 
	condition:
		any of ($a_*)
 
}