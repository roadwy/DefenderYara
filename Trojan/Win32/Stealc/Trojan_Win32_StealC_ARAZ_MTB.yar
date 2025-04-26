
rule Trojan_Win32_StealC_ARAZ_MTB{
	meta:
		description = "Trojan:Win32/StealC.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 04 3e 2c ?? 34 ?? 88 04 3e 46 57 e8 ?? ?? ?? ?? 59 3b f0 72 ea } //2
		$a_01_1 = {53 8d 44 24 14 89 5c 24 14 50 53 68 3f 00 0f 00 53 53 53 8d 84 24 3c 04 00 00 50 68 01 00 00 80 ff } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}
rule Trojan_Win32_StealC_ARAZ_MTB_2{
	meta:
		description = "Trojan:Win32/StealC.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 6d 6f 6e 65 72 6f 2d 70 72 6f 6a 65 63 74 5c 6d 6f 6e 65 72 6f 2d 63 6f 72 65 } //2 SOFTWARE\monero-project\monero-core
		$a_01_1 = {5c 4d 6f 6e 65 72 6f 5c 77 61 6c 6c 65 74 2e 6b 65 79 73 } //2 \Monero\wallet.keys
		$a_01_2 = {22 77 65 62 53 6f 63 6b 65 74 44 65 62 75 67 67 65 72 55 72 6c 22 3a } //2 "webSocketDebuggerUrl":
		$a_01_3 = {73 74 65 61 6d 5f 74 6f 6b 65 6e 73 2e 74 78 74 } //2 steam_tokens.txt
		$a_01_4 = {4f 70 75 73 20 54 68 65 61 74 72 65 20 77 61 73 20 66 6f 75 6e 64 65 64 20 62 79 } //2 Opus Theatre was founded by
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}