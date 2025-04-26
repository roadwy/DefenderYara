
rule Trojan_Win32_CoinMiner_RM_MTB{
	meta:
		description = "Trojan:Win32/CoinMiner.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 3a 5c 43 72 79 70 74 6f 4e 69 67 68 74 5c 62 69 74 6d 6f 6e 65 72 6f 2d 6d 61 73 74 65 72 5c 73 72 63 5c 6d 69 6e 65 72 5c 52 65 6c 65 61 73 65 5c 43 72 79 70 74 6f 2e 70 64 62 } //10 E:\CryptoNight\bitmonero-master\src\miner\Release\Crypto.pdb
		$a_01_1 = {62 79 6b 5c 3a 32 4c } //10 byk\:2L
		$a_01_2 = {41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73 } //1 AdjustTokenPrivileges
		$a_01_3 = {4c 6f 61 64 4c 69 62 72 61 72 79 41 } //1 LoadLibraryA
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=22
 
}