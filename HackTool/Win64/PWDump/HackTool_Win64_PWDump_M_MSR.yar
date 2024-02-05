
rule HackTool_Win64_PWDump_M_MSR{
	meta:
		description = "HackTool:Win64/PWDump.M!MSR,SIGNATURE_TYPE_PEHSTR,03 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 77 73 72 76 2e 65 78 65 } //01 00 
		$a_01_1 = {73 74 61 72 74 69 6e 67 20 64 6c 6c 20 69 6e 6a 65 63 74 69 6f 6e } //01 00 
		$a_01_2 = {63 72 65 61 74 65 72 65 6d 6f 74 65 74 68 72 65 61 64 20 6f 6b } //01 00 
		$a_01_3 = {73 65 72 76 70 77 36 34 2e 65 78 65 } //01 00 
		$a_01_4 = {6c 73 61 65 78 74 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}