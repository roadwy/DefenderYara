
rule Backdoor_MacOS_EggShell_D_MTB{
	meta:
		description = "Backdoor:MacOS/EggShell.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {65 79 4a 6b 5a 57 4a 31 5a 79 49 36 49 47 5a 68 62 48 4e 6c 4c 43 41 69 61 58 41 69 4f 69 41 69 4f 54 4d 75 4d 54 63 77 4c 6a 63 32 4c 6a 45 33 4f 53 49 73 49 43 4a 77 62 33 4a 30 49 6a 6f 67 4d 6a 49 34 4d 58 30 } //2 eyJkZWJ1ZyI6IGZhbHNlLCAiaXAiOiAiOTMuMTcwLjc2LjE3OSIsICJwb3J0IjogMjI4MX0
		$a_00_1 = {73 63 72 65 65 6e 2e 69 6e 66 6f 2e 73 77 74 65 73 74 2e 72 75 2f 6b 6e 6f 63 6b 2e 70 68 70 } //1 screen.info.swtest.ru/knock.php
		$a_00_2 = {6d 6f 69 6d 7a 2f 43 6f 69 6e 54 69 63 6b 65 72 2f 6d 61 73 74 65 72 2f 63 6f 69 6e 73 2e 70 6c 69 73 74 } //1 moimz/CoinTicker/master/coins.plist
		$a_00_3 = {69 73 42 74 63 4d 61 72 6b 65 74 } //1 isBtcMarket
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}