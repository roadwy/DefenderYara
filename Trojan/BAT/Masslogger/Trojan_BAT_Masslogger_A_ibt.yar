
rule Trojan_BAT_Masslogger_A_ibt{
	meta:
		description = "Trojan:BAT/Masslogger.A!ibt,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 08 00 00 "
		
	strings :
		$a_80_0 = {52 4f 4f 54 5c 53 65 63 75 72 69 74 79 43 65 6e 74 65 72 } //ROOT\SecurityCenter  1
		$a_80_1 = {41 6e 74 69 76 69 72 75 73 50 72 6f 64 75 63 74 } //AntivirusProduct  1
		$a_80_2 = {41 6e 74 69 53 70 79 57 61 72 65 50 72 6f 64 75 63 74 } //AntiSpyWareProduct  1
		$a_80_3 = {2f 43 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e 20 33 20 3e 20 6e 75 6c 20 26 20 64 65 6c } ///C ping 127.0.0.1 -n 3 > nul & del  1
		$a_80_4 = {6d 6f 6e 65 72 6f 2d 70 72 6f 6a 65 63 74 } //monero-project  10
		$a_80_5 = {5c 45 74 68 65 72 65 75 6d 5c 77 61 6c 6c 65 74 73 } //\Ethereum\wallets  10
		$a_80_6 = {73 65 74 74 69 6e 67 73 43 6f 69 6e 6f 6d 69 5c 77 61 6c 6c 65 74 5f 64 62 } //settingsCoinomi\wallet_db  10
		$a_80_7 = {43 68 72 6f 6d 65 2f 46 69 72 65 77 61 6c 6c 50 72 6f 64 75 63 74 } //Chrome/FirewallProduct  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*10+(#a_80_5  & 1)*10+(#a_80_6  & 1)*10+(#a_80_7  & 1)*1) >=33
 
}