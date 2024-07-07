
rule Trojan_Win64_CoinMiner_EM_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 8d 40 01 41 8b c1 41 ff c1 f7 f7 0f b6 04 32 41 30 40 ff } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}
rule Trojan_Win64_CoinMiner_EM_MTB_2{
	meta:
		description = "Trojan:Win64/CoinMiner.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 69 6e 69 6e 67 2e 73 75 62 73 63 72 69 62 65 } //1 mining.subscribe
		$a_01_1 = {63 70 75 6d 69 6e 65 72 2f 31 2e 30 2e 34 } //1 cpuminer/1.0.4
		$a_01_2 = {58 2d 4d 69 6e 69 6e 67 2d 45 78 74 65 6e 73 69 6f 6e 73 3a 20 6d 69 64 73 74 61 74 65 } //1 X-Mining-Extensions: midstate
		$a_01_3 = {58 2d 4c 6f 6e 67 2d 50 6f 6c 6c 69 6e 67 } //1 X-Long-Polling
		$a_01_4 = {58 2d 52 65 6a 65 63 74 2d 52 65 61 73 6f 6e } //1 X-Reject-Reason
		$a_01_5 = {58 2d 53 74 72 61 74 75 6d } //1 X-Stratum
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_Win64_CoinMiner_EM_MTB_3{
	meta:
		description = "Trojan:Win64/CoinMiner.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 57 } //1 ShellExecuteExW
		$a_01_1 = {47 65 74 54 65 6d 70 46 69 6c 65 4e 61 6d 65 57 } //1 GetTempFileNameW
		$a_01_2 = {4c 6f 61 64 4c 69 62 72 61 72 79 45 78 57 } //1 LoadLibraryExW
		$a_81_3 = {40 65 63 68 6f 20 6f 66 66 } //1 @echo off
		$a_01_4 = {73 74 61 72 74 20 61 62 63 2e 76 62 73 } //1 start abc.vbs
		$a_01_5 = {73 74 61 72 74 20 65 74 68 65 72 65 75 6d 2d 63 6c 61 73 73 69 63 2d 66 32 70 6f 6f 6c 2e 62 61 74 } //1 start ethereum-classic-f2pool.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}