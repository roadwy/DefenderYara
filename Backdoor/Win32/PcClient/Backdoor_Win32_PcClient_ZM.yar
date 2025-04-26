
rule Backdoor_Win32_PcClient_ZM{
	meta:
		description = "Backdoor:Win32/PcClient.ZM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 73 3d 00 00 2e 73 79 73 00 00 00 00 64 72 69 76 65 72 73 5c [0-06] 2e 6b 65 79 [0-06] 2e 65 78 65 [0-06] [61-7a] [6] [61-7a] [6] [61-7a] [6] 1-7a] 00 [0-06] [61-7a] [6] [61-7a] [6] [61-7a] [6] 1-7a] 00 [0-06] 2e [0-10] 25 73 25 30 35 78 2e 69 6d 69 [0-06] 47 6c 6f 62 61 6c 5c 70 73 25 30 36 78 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}