
rule Backdoor_Win32_PcClient_ZF{
	meta:
		description = "Backdoor:Win32/PcClient.ZF,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 [0-08] 44 6f 53 65 72 76 69 63 65 [0-06] 75 70 64 61 74 65 65 76 65 6e 74 00 25 73 3d 00 2e 73 79 73 [0-06] 64 72 69 76 65 72 73 5c [0-06] 2e 70 78 79 [0-06] 2e 64 72 76 [0-06] 2e 64 6c 6c } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Backdoor_Win32_PcClient_ZF_2{
	meta:
		description = "Backdoor:Win32/PcClient.ZF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 fa 63 7c f6 6a 63 6a 00 8d 95 04 ff ff ff 52 e8 ?? ?? 00 00 83 c4 0c 0f be 0e 83 f9 31 75 0e 8d 85 04 ff ff ff 50 6a 63 e8 ?? ?? 00 00 0f be 16 83 fa 32 75 0e } //1
		$a_01_1 = {83 fa 65 0f 94 c1 0f be 50 01 83 e1 01 83 fa 78 0f 94 c0 8b 55 d4 83 e0 01 23 c8 0f be 42 02 83 f8 65 0f 94 c2 83 e2 01 23 ca 74 7d } //1
		$a_01_2 = {72 62 00 63 3a 5c 00 5c 53 65 74 75 70 2e 00 77 62 00 63 3a 5c 00 6f 70 65 6e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}