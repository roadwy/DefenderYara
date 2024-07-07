
rule Trojan_Win32_CoinMiner_ASD_MTB{
	meta:
		description = "Trojan:Win32/CoinMiner.ASD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 61 6e 61 20 47 69 72 6c 66 69 72 65 6e 64 20 44 65 63 72 79 70 74 4f 72 20 32 2e 30 } //1 Wana Girlfirend DecryptOr 2.0
		$a_01_1 = {4f 6f 6f 70 73 2c 79 6f 75 72 20 67 69 72 6c 66 72 69 65 6e 64 20 68 61 76 61 20 62 65 65 6e 20 4e 54 52 21 } //1 Ooops,your girlfriend hava been NTR!
		$a_01_2 = {48 6f 77 20 74 6f 20 62 75 79 20 61 20 67 69 72 6c 66 72 69 65 6e 64 } //1 How to buy a girlfriend
		$a_01_3 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 53 79 73 74 65 32 2e 65 78 65 } //1 software\microsoft\windows\CurrentVersion\Run\Syste2.exe
		$a_01_4 = {47 69 72 6c 66 72 69 65 6e 64 2e 74 78 74 } //1 Girlfriend.txt
		$a_01_5 = {62 05 b5 22 d0 46 4b 2f 6f 20 4f 03 28 b5 ac de 63 20 0f 20 0f ac de 63 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}