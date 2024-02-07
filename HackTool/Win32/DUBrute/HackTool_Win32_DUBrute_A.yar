
rule HackTool_Win32_DUBrute_A{
	meta:
		description = "HackTool:Win32/DUBrute.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {5b 50 61 73 73 77 6f 72 64 5d 90 02 10 5b 4c 6f 67 69 6e 5d 90 02 10 25 75 73 65 72 6e 61 6d 65 25 90 00 } //01 00 
		$a_00_1 = {50 75 73 68 41 64 64 50 61 73 73 28 29 } //01 00  PushAddPass()
		$a_00_2 = {44 55 42 72 75 74 65 5f 76 } //00 00  DUBrute_v
	condition:
		any of ($a_*)
 
}