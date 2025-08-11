
rule Trojan_BAT_Stealer_EA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.EA!MTB,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 57 69 6e 64 6f 77 73 50 72 6f 64 75 63 74 4b 65 79 46 72 6f 6d 52 65 67 69 73 74 72 79 } //2 GetWindowsProductKeyFromRegistry
		$a_01_1 = {44 65 63 6f 64 65 50 72 6f 64 75 63 74 4b 65 79 57 69 6e 38 41 6e 64 55 70 } //2 DecodeProductKeyWin8AndUp
		$a_01_2 = {47 65 74 41 6c 6c 4e 65 74 77 6f 72 6b 49 6e 74 65 72 66 61 63 65 73 } //2 GetAllNetworkInterfaces
		$a_01_3 = {47 65 74 54 6f 6b 65 6e 73 46 72 6f 6d 44 69 73 63 6f 72 64 41 70 70 } //2 GetTokensFromDiscordApp
		$a_01_4 = {25 00 55 00 53 00 45 00 52 00 50 00 52 00 4f 00 46 00 49 00 4c 00 45 00 25 00 5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 } //2 %USERPROFILE%\AppData\Local\Google\Chrome\User Data
		$a_01_5 = {24 46 32 43 35 36 35 42 36 2d 45 34 46 35 2d 34 30 42 31 2d 38 43 34 30 2d 46 42 37 30 43 46 35 41 32 45 36 41 } //2 $F2C565B6-E4F5-40B1-8C40-FB70CF5A2E6A
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}