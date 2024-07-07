
rule Backdoor_Win32_PcClient_BX{
	meta:
		description = "Backdoor:Win32/PcClient.BX,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c1 70 e8 90 01 04 6a 00 6a 00 68 b6 05 00 00 90 00 } //1
		$a_03_1 = {32 75 00 00 77 90 01 01 81 7d 90 01 01 32 75 00 00 0f 84 90 01 04 8b 4d 90 01 01 81 e9 41 1f 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}