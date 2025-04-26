
rule Trojan_Win64_CoinMiner_PBH_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.PBH!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 66 69 6c 65 2e 68 69 74 6c 65 72 2e 66 61 6e 73 2f 78 6d 72 69 67 2e 65 78 65 } //2 http://file.hitler.fans/xmrig.exe
		$a_01_1 = {68 69 74 6c 65 72 4d 69 6e 65 72 54 6f 6f 6c } //2 hitlerMinerTool
		$a_01_2 = {52 65 6c 65 61 73 65 5c 58 6d 72 69 67 4d 6f 6e 69 74 6f 72 2e 70 64 62 } //2 Release\XmrigMonitor.pdb
		$a_01_3 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 74 20 2f 69 6d 20 } //1 taskkill /f /t /im 
		$a_01_4 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}