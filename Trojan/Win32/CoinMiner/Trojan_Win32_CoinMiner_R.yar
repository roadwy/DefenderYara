
rule Trojan_Win32_CoinMiner_R{
	meta:
		description = "Trojan:Win32/CoinMiner.R,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 00 6f 00 63 00 61 00 6c 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 } //1 LocalSessionManager
		$a_01_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {73 6f 63 6b 73 3d 31 6a 62 66 74 70 2e 6e 6f 2d 69 70 2e 6f 72 67 } //1 socks=1jbftp.no-ip.org
		$a_01_3 = {68 74 74 70 3a 2f 2f 6d 69 6e 65 2e 70 6f 6f 6c 2d 78 2e 65 75 } //1 http://mine.pool-x.eu
		$a_01_4 = {6d 69 64 73 74 61 74 65 7c 64 61 74 61 7c 68 61 73 68 31 7c 74 61 72 67 65 74 } //1 midstate|data|hash1|target
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_CoinMiner_R_2{
	meta:
		description = "Trojan:Win32/CoinMiner.R,SIGNATURE_TYPE_PEHSTR_EXT,7a 00 7a 00 09 00 00 "
		
	strings :
		$a_01_0 = {73 6f 63 6b 73 3d 31 6a 62 66 74 70 2e 6e 6f 2d 69 70 2e 6f 72 67 } //100 socks=1jbftp.no-ip.org
		$a_01_1 = {73 6f 63 6b 73 3d 6d 70 78 79 2e 68 6f 70 74 6f 2e 6f 72 67 } //100 socks=mpxy.hopto.org
		$a_01_2 = {4c 00 6f 00 63 00 61 00 6c 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 } //10 LocalSessionManager
		$a_01_3 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //10 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_4 = {4c 50 6f 58 43 4a 45 41 64 4e 7a 58 68 55 4a 4b 63 43 39 35 38 79 69 68 52 34 6d 50 58 4a 52 46 73 4b } //1 LPoXCJEAdNzXhUJKcC958yihR4mPXJRFsK
		$a_01_5 = {6a 69 6d 6d 79 63 72 69 63 6b 65 74 73 } //1 jimmycrickets
		$a_01_6 = {6d 69 6e 65 2e 70 6f 6f 6c 2d 78 2e 65 75 } //1 mine.pool-x.eu
		$a_01_7 = {70 6f 6f 6c 2e 64 6c 75 6e 63 68 2e 6e 65 74 3a 39 33 32 37 } //1 pool.dlunch.net:9327
		$a_01_8 = {6c 69 74 65 2e 63 6f 69 6e 2d 70 6f 6f 6c 2e 63 6f 6d 3a 38 33 33 39 } //1 lite.coin-pool.com:8339
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=122
 
}