
rule Backdoor_Win32_PcClient_ZB{
	meta:
		description = "Backdoor:Win32/PcClient.ZB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {32 30 30 00 68 74 74 70 3a 2f 2f 25 73 00 00 00 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 32 3b 20 53 56 31 3b 20 2e 4e 45 54 20 43 4c 52 } //1
		$a_01_1 = {20 31 2e 31 2e 34 33 32 32 29 00 00 68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 25 73 25 64 25 30 38 64 00 00 00 69 6e 64 65 78 2e 61 73 70 3f 00 00 54 6f 44 6f 00 00 00 00 77 62 00 00 53 56 43 48 4f 53 54 2e 45 58 45 00 72 62 00 00 53 65 44 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}