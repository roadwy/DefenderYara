
rule MonitoringTool_Win32_Beyond{
	meta:
		description = "MonitoringTool:Win32/Beyond,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {7b 4e 55 4d 4c 43 4b 7d 20 } //01 00  {NUMLCK} 
		$a_01_1 = {7b 43 4c 45 41 52 2d 50 41 44 35 7d 20 } //0a 00  {CLEAR-PAD5} 
		$a_01_2 = {40 2a 2a 2d 2a 2a 40 00 } //02 00 
		$a_03_3 = {33 c6 44 24 90 01 01 32 c6 44 24 90 01 01 2e c6 44 24 90 01 01 64 90 00 } //02 00 
		$a_03_4 = {b3 61 b2 65 50 51 c6 45 90 01 01 44 c6 45 90 01 01 69 c6 45 90 01 01 73 90 00 } //02 00 
		$a_01_5 = {b2 65 b1 72 b3 61 b0 6c 88 55 } //02 00 
		$a_03_6 = {48 c6 44 24 90 01 01 6b c6 44 24 90 01 01 45 c6 44 24 90 01 01 78 c6 44 24 90 01 01 41 90 00 } //00 00 
		$a_00_7 = {80 10 00 00 8a f6 f6 eb ac fa ad } //ef 32 
	condition:
		any of ($a_*)
 
}