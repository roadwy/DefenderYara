
rule MonitoringTool_Win32_MegaSpy{
	meta:
		description = "MonitoringTool:Win32/MegaSpy,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 13 05 32 81 91 14 a1 b1 42 23 c1 52 d1 f0 33 } //01 00 
		$a_01_1 = {c4 d4 e4 f4 a5 b5 c5 d5 e5 f5 56 66 76 86 96 a6 } //01 00 
		$a_01_2 = {64 6f 20 4d 65 67 61 2d 53 70 79 20 65 78 70 69 72 6f 75 } //01 00 
		$a_01_3 = {4d 65 67 61 2d 53 70 79 20 6e 6f 76 61 6d 65 6e 74 65 20 75 74 69 6c 69 7a 65 } //00 00 
	condition:
		any of ($a_*)
 
}