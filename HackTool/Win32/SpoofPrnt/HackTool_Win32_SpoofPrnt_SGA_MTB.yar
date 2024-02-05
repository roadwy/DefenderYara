
rule HackTool_Win32_SpoofPrnt_SGA_MTB{
	meta:
		description = "HackTool:Win32/SpoofPrnt.SGA!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 64 6f 77 6e 6c 6f 61 64 } //01 00 
		$a_01_1 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //01 00 
		$a_01_2 = {72 65 67 53 70 6f 6f 66 } //01 00 
		$a_01_3 = {4b 65 79 41 75 74 68 } //01 00 
		$a_01_4 = {77 65 62 68 6f 6f 6b } //01 00 
		$a_01_5 = {67 65 74 53 70 6f 6f 66 69 6e 67 52 65 67 69 73 74 72 79 4b 65 79 73 } //00 00 
	condition:
		any of ($a_*)
 
}