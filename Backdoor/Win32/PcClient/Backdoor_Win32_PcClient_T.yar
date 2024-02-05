
rule Backdoor_Win32_PcClient_T{
	meta:
		description = "Backdoor:Win32/PcClient.T,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {f3 ab 66 ab aa c6 85 90 01 04 5c c6 85 90 01 04 73 c6 85 90 01 04 76 c6 85 90 01 04 63 c6 85 90 01 04 68 c6 85 90 01 04 6f c6 85 90 01 04 73 c6 85 90 01 04 74 c6 85 90 01 04 2e c6 85 90 01 04 65 c6 85 90 01 04 78 c6 85 90 00 } //01 00 
		$a_00_1 = {64 72 69 76 65 72 73 5c } //01 00 
		$a_00_2 = {25 73 25 30 37 78 2e 69 6e 69 } //01 00 
		$a_00_3 = {47 6c 6f 62 61 6c 5c 70 73 25 30 38 78 } //00 00 
	condition:
		any of ($a_*)
 
}