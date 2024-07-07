
rule Trojan_Win64_ClipBanker_X_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.X!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 6f 6e 65 72 6f 20 61 64 64 72 65 73 73 20 64 65 74 65 63 74 65 64 20 69 6e 20 63 6c 69 70 62 6f 61 72 64 } //2 Monero address detected in clipboard
		$a_01_1 = {4c 69 74 65 63 6f 69 6e 20 61 64 64 72 65 73 73 20 64 65 74 65 63 74 65 64 20 69 6e 20 63 6c 69 70 62 6f 61 72 64 } //2 Litecoin address detected in clipboard
		$a_01_2 = {42 69 74 63 6f 69 6e 20 61 64 64 72 65 73 73 20 64 65 74 65 63 74 65 64 20 69 6e 20 63 6c 69 70 62 6f 61 72 64 } //2 Bitcoin address detected in clipboard
		$a_01_3 = {45 74 68 65 72 65 75 6d 20 61 64 64 72 65 73 73 20 64 65 74 65 63 74 65 64 20 69 6e 20 63 6c 69 70 62 6f 61 72 64 } //2 Ethereum address detected in clipboard
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}