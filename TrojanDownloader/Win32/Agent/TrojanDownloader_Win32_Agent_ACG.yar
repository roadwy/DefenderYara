
rule TrojanDownloader_Win32_Agent_ACG{
	meta:
		description = "TrojanDownloader:Win32/Agent.ACG,SIGNATURE_TYPE_PEHSTR,4b 01 4b 01 08 00 00 "
		
	strings :
		$a_01_0 = {76 65 72 79 73 69 6c 65 6e 74 } //100 verysilent
		$a_01_1 = {41 75 74 6f 49 6e 73 51 79 75 6c 65 } //100 AutoInsQyule
		$a_01_2 = {7b 33 42 37 43 42 45 45 39 2d 38 39 41 32 2d 34 34 39 63 2d 42 38 38 45 2d 32 32 34 39 38 46 42 41 42 30 30 35 7d } //100 {3B7CBEE9-89A2-449c-B88E-22498FBAB005}
		$a_01_3 = {73 65 74 75 70 2e 65 78 65 } //10 setup.exe
		$a_01_4 = {51 79 75 6c 65 49 6e 73 74 61 6c 6c 2e 65 78 65 } //10 QyuleInstall.exe
		$a_01_5 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //10 InternetReadFile
		$a_01_6 = {68 74 74 70 3a 2f 2f 75 70 64 61 74 65 2e 71 79 75 6c 65 2e 63 6f 6d 2f 73 65 74 75 70 2e 65 78 65 } //1 http://update.qyule.com/setup.exe
		$a_01_7 = {68 74 74 70 3a 2f 2f 32 31 38 2e 32 30 34 2e 32 35 33 2e 31 34 35 2f 73 65 74 75 70 2e 65 78 65 } //1 http://218.204.253.145/setup.exe
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=331
 
}