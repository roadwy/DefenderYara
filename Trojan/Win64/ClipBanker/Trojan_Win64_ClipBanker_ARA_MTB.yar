
rule Trojan_Win64_ClipBanker_ARA_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 54 72 75 73 74 57 61 6c 6c 65 74 45 6c 65 63 74 72 75 6d 57 61 6c 6c 65 74 2e 65 78 65 } //5 \TrustWalletElectrumWallet.exe
		$a_01_1 = {5c 63 6c 69 70 62 6f 61 72 64 53 65 72 76 69 63 65 2e 65 78 65 } //5 \clipboardService.exe
		$a_01_2 = {45 78 65 63 75 74 61 62 6c 65 20 63 6f 70 69 65 64 20 74 6f 20 53 74 61 72 74 75 70 20 66 6f 6c 64 65 72 } //2 Executable copied to Startup folder
		$a_01_3 = {72 66 35 76 50 79 31 48 63 4a 32 32 37 42 66 4c 71 69 5a 65 4b 58 71 78 79 45 52 74 79 51 58 5a 7a 57 } //2 rf5vPy1HcJ227BfLqiZeKXqxyERtyQXZzW
		$a_01_4 = {44 51 39 38 54 32 67 6a 6d 56 4d 55 76 68 33 63 47 67 61 59 69 58 6d 31 58 76 32 52 37 6d 52 36 65 44 } //2 DQ98T2gjmVMUvh3cGgaYiXm1Xv2R7mR6eD
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=11
 
}