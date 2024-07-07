
rule Trojan_Win32_CoinMiner_ABS_MTB{
	meta:
		description = "Trojan:Win32/CoinMiner.ABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 8d 14 e5 b7 a9 d3 d4 8a 06 66 0f ca 48 8d 96 48 b6 8c c4 48 ff c6 39 c2 66 0f be d2 28 d8 88 d2 f9 0f ba f2 0b d2 de c0 c0 04 66 0f ca 66 0f b6 d1 89 d2 fe c8 e9 a7 0f 00 00 } //1
		$a_01_1 = {64 6b 6a 69 68 67 66 64 65 74 73 72 71 70 6f 6e 64 6d } //1 dkjihgfdetsrqpondm
		$a_01_2 = {45 3a 5c 43 72 79 70 74 6f 4e 69 67 68 74 5c 62 69 74 6d 6f 6e 65 72 6f 2d 6d 61 73 74 65 72 5c 73 72 63 5c 6d 69 6e 65 72 5c 78 36 34 5c 43 50 55 2d 52 65 6c 65 61 73 65 5c 43 72 79 70 74 6f 2e 70 64 62 } //1 E:\CryptoNight\bitmonero-master\src\miner\x64\CPU-Release\Crypto.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}