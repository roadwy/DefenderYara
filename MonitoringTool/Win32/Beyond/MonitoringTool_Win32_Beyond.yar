
rule MonitoringTool_Win32_Beyond{
	meta:
		description = "MonitoringTool:Win32/Beyond,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_01_0 = {7b 4e 55 4d 4c 43 4b 7d 20 } //1 {NUMLCK} 
		$a_01_1 = {7b 43 4c 45 41 52 2d 50 41 44 35 7d 20 } //1 {CLEAR-PAD5} 
		$a_01_2 = {40 2a 2a 2d 2a 2a 40 00 } //10
		$a_03_3 = {33 c6 44 24 ?? 32 c6 44 24 ?? 2e c6 44 24 ?? 64 } //2
		$a_03_4 = {b3 61 b2 65 50 51 c6 45 ?? 44 c6 45 ?? 69 c6 45 ?? 73 } //2
		$a_01_5 = {b2 65 b1 72 b3 61 b0 6c 88 55 } //2
		$a_03_6 = {48 c6 44 24 ?? 6b c6 44 24 ?? 45 c6 44 24 ?? 78 c6 44 24 ?? 41 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10+(#a_03_3  & 1)*2+(#a_03_4  & 1)*2+(#a_01_5  & 1)*2+(#a_03_6  & 1)*2) >=14
 
}