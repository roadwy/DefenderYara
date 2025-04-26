
rule PWS_BAT_Stimilini_F{
	meta:
		description = "PWS:BAT/Stimilini.F,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 74 65 61 6d 53 74 65 61 6c 65 72 2e 50 72 6f 70 65 72 74 69 65 73 } //10 SteamStealer.Properties
		$a_01_1 = {50 61 72 73 65 53 74 65 61 6d 43 6f 6f 6b 69 65 73 } //1 ParseSteamCookies
		$a_01_2 = {46 69 6c 74 65 72 42 79 52 61 72 69 74 79 } //1 FilterByRarity
		$a_01_3 = {73 65 6e 64 4d 65 73 73 61 67 65 54 6f 46 72 69 65 6e 64 73 } //1 sendMessageToFriends
		$a_01_4 = {61 64 64 49 74 65 6d 73 54 6f 53 74 65 61 6c } //1 addItemsToSteal
		$a_01_5 = {61 63 63 65 70 74 41 6c 6c 49 6e 63 6f 6d 69 6e 67 54 72 61 64 65 73 } //1 acceptAllIncomingTrades
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=12
 
}
rule PWS_BAT_Stimilini_F_2{
	meta:
		description = "PWS:BAT/Stimilini.F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 00 6f 00 67 00 69 00 6e 00 3d 00 7b 00 30 00 7d 00 26 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3d 00 7b 00 31 00 7d 00 } //1 login={0}&password={1}
		$a_00_1 = {72 00 61 00 69 00 64 00 63 00 61 00 6c 00 6c 00 73 00 6f 00 66 00 74 00 2e 00 6f 00 72 00 67 00 2f 00 73 00 74 00 65 00 61 00 6d 00 2f 00 67 00 61 00 74 00 65 00 2e 00 70 00 68 00 70 00 } //2 raidcallsoft.org/steam/gate.php
		$a_00_2 = {5f 00 73 00 74 00 65 00 61 00 6d 00 2e 00 65 00 78 00 65 00 } //1 _steam.exe
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1) >=4
 
}
rule PWS_BAT_Stimilini_F_3{
	meta:
		description = "PWS:BAT/Stimilini.F,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {25 00 73 00 74 00 65 00 61 00 6d 00 4c 00 6f 00 67 00 69 00 6e 00 } //1 %steamLogin
		$a_01_1 = {74 00 72 00 61 00 64 00 65 00 6f 00 66 00 66 00 65 00 72 00 2f 00 6e 00 65 00 77 00 2f 00 73 00 65 00 6e 00 64 00 } //1 tradeoffer/new/send
		$a_01_2 = {72 00 67 00 49 00 6e 00 76 00 65 00 6e 00 74 00 6f 00 72 00 79 00 } //1 rgInventory
		$a_01_3 = {63 00 6f 00 6e 00 74 00 65 00 78 00 74 00 69 00 64 00 25 00 32 00 32 00 25 00 33 00 41 00 32 00 25 00 32 00 43 00 25 00 32 00 32 00 61 00 6d 00 6f 00 75 00 6e 00 74 00 } //1 contextid%22%3A2%2C%22amount
		$a_01_4 = {61 00 73 00 73 00 65 00 74 00 69 00 64 00 25 00 32 00 32 00 25 00 33 00 41 00 25 00 32 00 32 00 } //1 assetid%22%3A%22
		$a_01_5 = {26 00 74 00 72 00 61 00 64 00 65 00 6f 00 66 00 66 00 65 00 72 00 6d 00 65 00 73 00 73 00 61 00 67 00 65 00 3d 00 26 00 6a 00 73 00 6f 00 6e 00 5f 00 74 00 72 00 61 00 64 00 65 00 6f 00 66 00 66 00 65 00 72 00 3d 00 } //1 &tradeoffermessage=&json_tradeoffer=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}