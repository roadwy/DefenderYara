
rule TrojanDropper_Win32_PcClient_A{
	meta:
		description = "TrojanDropper:Win32/PcClient.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 73 5c 52 25 63 6d 25 63 74 25 63 43 2e 64 6c 6c 00 00 00 52 73 54 72 41 79 2e 65 58 65 00 } //1
		$a_03_1 = {8b 54 24 30 8b 0c 3e 03 f7 8b e9 2b 6a 1c 8d 42 1c 83 c4 18 3b 6a 38 73 ?? 8b 28 8b 54 24 1c 8b 44 24 30 2b cd 03 ca } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}