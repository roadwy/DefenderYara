
rule Backdoor_Win32_PcClient_ZH{
	meta:
		description = "Backdoor:Win32/PcClient.ZH,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 90 02 08 4c 6f 61 64 50 72 6f 66 69 6c 65 90 02 06 2e 73 79 73 90 02 08 64 72 69 76 65 72 73 5c 90 02 08 2e 64 72 76 90 02 08 2e 64 6c 6c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}