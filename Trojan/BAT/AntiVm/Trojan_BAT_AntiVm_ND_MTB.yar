
rule Trojan_BAT_AntiVm_ND_MTB{
	meta:
		description = "Trojan:BAT/AntiVm.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0b 00 00 "
		
	strings :
		$a_81_0 = {6e 75 52 5c 6e 6f 69 73 72 65 56 74 6e 65 72 72 75 43 5c 73 77 6f 64 6e 69 57 5c 74 66 6f 73 6f 72 63 69 4d 5c 65 72 61 77 74 66 6f 53 } //2 nuR\noisreVtnerruC\swodniW\tfosorciM\erawtfoS
		$a_81_1 = {56 69 72 74 75 61 6c 42 6f 78 } //1 VirtualBox
		$a_81_2 = {76 6d 77 61 72 65 } //1 vmware
		$a_81_3 = {53 62 69 65 44 6c 6c 2e 64 6c 6c } //1 SbieDll.dll
		$a_81_4 = {45 72 67 6f 5f 57 61 6c 6c 65 74 } //1 Ergo_Wallet
		$a_81_5 = {45 6c 65 63 74 72 75 6d } //1 Electrum
		$a_81_6 = {42 69 74 63 6f 69 6e 5f 43 6f 72 65 } //1 Bitcoin_Core
		$a_81_7 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 41 6e 74 69 76 69 72 75 73 50 72 6f 64 75 63 74 } //1 Select * from AntivirusProduct
		$a_81_8 = {2f 63 20 74 61 73 6b 6b 69 6c 6c 2e 65 78 65 20 2f 69 6d 20 63 68 72 6f 6d 65 2e 65 78 65 20 2f 66 } //1 /c taskkill.exe /im chrome.exe /f
		$a_81_9 = {2f 63 20 73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 66 20 2f 73 63 20 6f 6e 6c 6f 67 6f 6e 20 2f 72 6c 20 68 69 67 68 65 73 74 20 2f 74 6e } //1 /c schtasks /create /f /sc onlogon /rl highest /tn
		$a_81_10 = {47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 63 61 6c 20 45 78 74 65 6e 73 69 6f 6e 20 53 65 74 74 69 6e 67 73 } //1 Google\Chrome\User Data\Default\Local Extension Settings
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=12
 
}