
rule Trojan_Win64_CoinMiner_SPQA_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.SPQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_81_0 = {57 69 6e 64 6f 77 73 5c 57 69 6e 53 5c 78 63 6f 70 79 2e 65 78 65 } //2 Windows\WinS\xcopy.exe
		$a_81_1 = {2d 6f 20 78 6d 72 2e 70 6f 6f 6c 2e 6d 69 6e 65 72 67 61 74 65 2e 63 6f 6d 3a 34 35 37 30 31 20 } //2 -o xmr.pool.minergate.com:45701 
		$a_81_2 = {2d 75 20 34 39 50 37 70 74 74 4c 75 36 6a 4b 34 67 4d 45 47 4d 34 75 6a 6b 44 39 75 67 43 53 55 4d 61 69 64 51 51 4d 66 64 57 7a 38 6b 4d 70 62 5a 66 7a 62 6b 4c 4e 79 6f 43 48 6b 79 5a 64 33 74 6a 43 67 38 61 6f 5a 47 71 51 53 69 4a 52 51 68 71 68 63 6f 57 7a 43 48 45 50 4d 34 44 4e 55 78 50 20 2d 2d 63 70 75 2d 70 72 69 6f 72 69 74 79 3d 30 20 2d 70 20 78 20 2d 6b } //2 -u 49P7pttLu6jK4gMEGM4ujkD9ugCSUMaidQQMfdWz8kMpbZfzbkLNyoCHkyZd3tjCg8aoZGqQSiJRQhqhcoWzCHEPM4DNUxP --cpu-priority=0 -p x -k
		$a_81_3 = {25 31 38 5c 53 61 6d 75 72 61 69 56 61 6e 64 61 6c 69 73 6d 2e 65 78 65 } //1 %18\SamuraiVandalism.exe
		$a_81_4 = {53 59 53 54 45 4d 5c 43 6f 6e 74 72 6f 6c 53 65 74 30 30 31 5c 73 65 72 76 69 63 65 73 5c 57 4d 53 5c 50 61 72 61 6d 65 74 65 72 73 5c 41 70 70 45 78 69 74 } //1 SYSTEM\ControlSet001\services\WMS\Parameters\AppExit
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=8
 
}