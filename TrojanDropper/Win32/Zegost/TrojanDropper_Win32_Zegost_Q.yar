
rule TrojanDropper_Win32_Zegost_Q{
	meta:
		description = "TrojanDropper:Win32/Zegost.Q,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 50 61 74 68 73 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 00 } //1
		$a_01_1 = {22 25 73 22 20 61 62 6f 75 74 3a 62 6c 61 6e 6b 00 } //1
		$a_00_2 = {53 74 6f 72 6d 20 64 64 6f 73 20 53 65 72 76 65 72 } //1 Storm ddos Server
		$a_02_3 = {b9 00 08 00 00 33 c0 8d bc 24 ?? ?? 00 00 50 f3 ab 8b 83 ?? 00 00 00 8d 94 24 ?? ?? 00 00 68 00 20 00 00 52 50 ff d5 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}