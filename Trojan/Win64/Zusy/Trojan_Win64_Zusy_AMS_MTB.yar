
rule Trojan_Win64_Zusy_AMS_MTB{
	meta:
		description = "Trojan:Win64/Zusy.AMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_80_0 = {53 74 65 61 6c 65 72 44 4c 4c 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 53 54 45 41 4c 45 52 44 4c 4c 2e 70 64 62 } //StealerDLL\x64\Release\STEALERDLL.pdb  4
		$a_80_1 = {4d 6f 6e 65 72 6f 5c 77 61 6c 6c 65 74 73 } //Monero\wallets  2
		$a_80_2 = {54 68 75 6e 64 65 72 62 69 72 64 5c 50 72 6f 66 69 6c 65 73 } //Thunderbird\Profiles  2
		$a_80_3 = {39 33 37 35 43 46 46 30 34 31 33 31 31 31 64 33 42 38 38 41 30 30 31 30 34 42 32 41 36 36 37 36 } //9375CFF0413111d3B88A00104B2A6676  1
		$a_80_4 = {6e 65 74 73 68 20 77 6c 61 6e 20 73 68 6f 77 20 70 72 6f 66 69 6c 65 73 } //netsh wlan show profiles  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=10
 
}
rule Trojan_Win64_Zusy_AMS_MTB_2{
	meta:
		description = "Trojan:Win64/Zusy.AMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_80_0 = {78 53 59 45 66 4a 75 45 66 77 48 77 46 6d 38 63 63 67 6c 59 59 34 66 78 70 58 59 4a 54 70 71 54 71 54 33 52 76 72 31 57 35 36 34 30 61 61 62 32 } //xSYEfJuEfwHwFm8ccglYY4fxpXYJTpqTqT3Rvr1W5640aab2  3
		$a_80_1 = {5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 77 65 62 64 61 74 61 5c 69 6e 66 6f 2e 64 61 74 } //\Users\Public\webdata\info.dat  3
		$a_80_2 = {57 65 62 53 76 63 20 2e 2e 2e 20 52 65 67 69 73 74 65 72 4d 61 63 68 69 6e 65 20 77 5f 73 55 55 49 44 } //WebSvc ... RegisterMachine w_sUUID  1
		$a_80_3 = {2f 43 20 74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 25 73 20 2f 46 } ///C taskkill /IM %s /F  1
		$a_80_4 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 41 70 70 6c 69 63 61 74 69 6f 6e 5c 63 68 72 6f 6d 65 2e 65 78 65 22 20 2d 2d 72 65 73 74 6f 72 65 2d 6c 61 73 74 2d 73 65 73 73 69 6f 6e } //\Google\Chrome\Application\chrome.exe" --restore-last-session  1
		$a_80_5 = {64 61 73 68 2e 7a 69 6e 74 72 61 63 6b 2e 63 6f 6d } //dash.zintrack.com  1
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=10
 
}