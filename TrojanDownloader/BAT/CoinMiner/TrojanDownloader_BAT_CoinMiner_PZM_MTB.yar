
rule TrojanDownloader_BAT_CoinMiner_PZM_MTB{
	meta:
		description = "TrojanDownloader:BAT/CoinMiner.PZM!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 34 36 2e 38 2e 37 38 2e 31 37 32 2f 6d 69 6e 69 72 2e 7a 69 70 } //5 http://46.8.78.172/minir.zip
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 62 72 6f 77 73 65 72 5f 62 72 6f 6b 65 72 2e 65 78 65 } //1 taskkill /f /im browser_broker.exe
		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 70 79 74 68 6f 6e 2e 65 78 65 } //1 taskkill /f /im python.exe
		$a_01_3 = {6d 69 6e 65 72 6c 6f 6c 2e 7a 69 70 } //1 minerlol.zip
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}