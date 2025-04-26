
rule Trojan_BAT_RedlineStealer_RPY_MTB{
	meta:
		description = "Trojan:BAT/RedlineStealer.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {71 1f 00 00 01 20 9a 00 00 00 61 d2 81 1f 00 00 01 02 50 06 8f 1f 00 00 01 25 71 1f 00 00 01 1f 40 58 d2 81 1f 00 00 01 02 50 06 8f 1f 00 00 01 25 71 1f 00 00 01 1f 43 59 d2 81 1f 00 00 01 02 50 06 8f 1f 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_RedlineStealer_RPY_MTB_2{
	meta:
		description = "Trojan:BAT/RedlineStealer.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {6c 00 6f 00 67 00 69 00 6e 00 75 00 73 00 65 00 72 00 73 00 2e 00 76 00 64 00 66 00 } //1 loginusers.vdf
		$a_01_1 = {54 00 6f 00 6b 00 65 00 6e 00 73 00 2e 00 74 00 78 00 74 00 } //1 Tokens.txt
		$a_01_2 = {4b 00 61 00 7a 00 61 00 6b 00 68 00 73 00 74 00 61 00 6e 00 } //1 Kazakhstan
		$a_01_3 = {52 00 75 00 73 00 73 00 69 00 61 00 } //1 Russia
		$a_01_4 = {73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //1 shell\open\command
		$a_01_5 = {61 00 70 00 69 00 2e 00 69 00 70 00 2e 00 73 00 62 00 2f 00 69 00 70 00 } //1 api.ip.sb/ip
		$a_01_6 = {41 6c 6c 57 61 6c 6c 65 74 73 } //1 AllWallets
		$a_01_7 = {57 68 6f 49 73 4c 6f 63 6b 69 6e 67 } //1 WhoIsLocking
		$a_01_8 = {47 65 74 42 72 6f 77 73 65 72 73 } //1 GetBrowsers
		$a_01_9 = {47 65 74 47 72 61 70 68 69 63 43 61 72 64 73 } //1 GetGraphicCards
		$a_01_10 = {51 75 65 72 79 41 56 } //1 QueryAV
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}