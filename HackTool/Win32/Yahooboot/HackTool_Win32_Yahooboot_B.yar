
rule HackTool_Win32_Yahooboot_B{
	meta:
		description = "HackTool:Win32/Yahooboot.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 4d 53 47 31 32 5f 53 63 72 69 70 74 65 64 4d 69 6e 64 5f 45 6e 63 72 79 70 74 } //01 00 
		$a_00_1 = {59 4d 53 47 2e 64 6c 6c } //01 00 
		$a_00_2 = {4e 6f 20 42 6f 74 73 20 4c 6f 61 64 65 64 21 } //01 00 
		$a_00_3 = {41 74 74 61 63 6b 20 43 6f 6d 70 6c 65 74 65 21 } //01 00 
		$a_00_4 = {45 39 42 6f 6f 74 65 72 } //01 00 
		$a_00_5 = {5c 53 6f 66 74 77 61 72 65 5c 41 50 69 72 61 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}