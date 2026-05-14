
rule Trojan_BAT_CookieStealer_A_AMTB{
	meta:
		description = "Trojan:BAT/CookieStealer.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {53 74 65 61 6c 57 61 6c 6c 65 74 73 } //StealWallets  1
		$a_80_1 = {5b 2a 5d 20 53 74 65 61 6c 69 6e 67 20 54 65 6c 65 67 72 61 6d 20 73 65 73 73 69 6f 6e 73 2e 2e 2e } //[*] Stealing Telegram sessions...  1
		$a_80_2 = {41 70 70 53 74 65 61 6c 65 72 73 } //AppStealers  1
		$a_80_3 = {41 6b 61 63 68 75 20 7c 20 74 2e 6d 65 2f 61 6b 34 63 68 75 } //Akachu | t.me/ak4chu  1
		$a_80_4 = {43 6f 6f 6b 69 65 53 74 65 61 6c 65 72 } //CookieStealer  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}