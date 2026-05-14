
rule Trojan_Win32_MoonriseRAT_AMTB{
	meta:
		description = "Trojan:Win32/MoonriseRAT!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 08 00 00 "
		
	strings :
		$a_01_0 = {49 3b 66 10 76 3b 48 83 ec 08 48 89 2c 24 48 8d 2c 24 89 05 f8 fb 57 00 83 3d 31 00 58 00 00 90 75 09 48 89 1d af 84 52 00 eb 0c } //5
		$a_80_1 = {6d 61 69 6e 2e 5f 66 53 74 65 61 6c 44 69 73 63 6f 72 64 } //main._fStealDiscord  2
		$a_80_2 = {6d 61 69 6e 2e 5f 66 53 74 65 61 6c 54 65 6c 65 67 72 61 6d } //main._fStealTelegram  2
		$a_80_3 = {6d 61 69 6e 2e 5f 66 53 74 65 61 6c 42 72 6f 77 73 65 72 73 } //main._fStealBrowsers  2
		$a_80_4 = {6d 61 69 6e 2e 5f 66 53 74 65 61 6c 57 69 46 69 } //main._fStealWiFi  2
		$a_80_5 = {6d 61 69 6e 2e 5f 66 53 74 65 61 6c 43 72 79 70 74 6f } //main._fStealCrypto  2
		$a_80_6 = {6d 61 69 6e 2e 5f 66 53 74 65 61 6c 53 79 73 74 65 6d } //main._fStealSystem  2
		$a_80_7 = {6d 61 69 6e 2e 5f 73 65 74 43 6c 69 70 62 6f 61 72 64 54 65 78 74 2e 66 75 6e 63 31 } //main._setClipboardText.func1  1
	condition:
		((#a_01_0  & 1)*5+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2+(#a_80_6  & 1)*2+(#a_80_7  & 1)*1) >=18
 
}