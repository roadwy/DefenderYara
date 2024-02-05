
rule HackTool_Win32_Honedol_A{
	meta:
		description = "HackTool:Win32/Honedol.A,SIGNATURE_TYPE_PEHSTR,64 00 64 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {48 44 20 41 6c 6c 20 69 6e 20 4f 6e 65 20 54 6f 6f 6c 20 56 25 73 20 28 25 73 29 } //0a 00 
		$a_01_1 = {50 61 73 73 77 30 72 64 } //0a 00 
		$a_01_2 = {43 6f 64 65 20 62 79 20 57 69 6c 6c 69 61 6d 20 48 65 6e 72 79 } //0a 00 
		$a_01_3 = {49 50 43 24 20 50 61 73 73 77 6f 72 64 20 53 63 61 6e 6e 65 72 } //00 00 
		$a_01_4 = {00 5d 04 00 00 c0 0d 03 80 5c 1e 00 00 c4 0d 03 80 00 00 01 00 08 00 08 00 ac 21 44 72 6f } //6a 2e 
	condition:
		any of ($a_*)
 
}