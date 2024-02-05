
rule HackTool_Win32_GameHack_J_MSR{
	meta:
		description = "HackTool:Win32/GameHack.J!MSR,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 4c 69 4e 47 54 72 61 69 6e 65 72 2e 63 6f 6d } //01 00 
		$a_01_1 = {62 62 73 2e 33 64 6d 67 61 6d 65 2e 63 6f 6d } //01 00 
		$a_01_2 = {66 6c 69 6e 67 74 72 61 69 6e 65 72 2e 63 6f 6d 2f 74 61 67 2f 6d 6f 6e 73 74 65 72 2d 68 75 6e 74 65 72 2d 77 6f 72 6c 64 } //01 00 
		$a_01_3 = {63 6f 70 79 20 63 6f 6e 73 74 72 75 63 74 6f 72 20 63 6c 6f 73 75 72 65 } //00 00 
		$a_01_4 = {00 5d } //04 00 
	condition:
		any of ($a_*)
 
}