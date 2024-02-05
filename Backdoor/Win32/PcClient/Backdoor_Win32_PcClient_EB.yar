
rule Backdoor_Win32_PcClient_EB{
	meta:
		description = "Backdoor:Win32/PcClient.EB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {f3 ab 66 ab aa c6 85 90 01 04 2e c6 85 90 01 04 73 c6 85 90 01 04 79 c6 85 90 01 04 73 80 a5 90 01 04 00 68 c8 00 00 00 90 00 } //01 00 
		$a_03_1 = {f3 ab 66 ab aa c6 85 90 01 04 7a c6 85 90 01 04 2e c6 85 90 01 04 64 c6 85 90 01 04 6c c6 85 90 01 04 6c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}