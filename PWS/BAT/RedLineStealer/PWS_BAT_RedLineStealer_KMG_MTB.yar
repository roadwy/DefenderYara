
rule PWS_BAT_RedLineStealer_KMG_MTB{
	meta:
		description = "PWS:BAT/RedLineStealer.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_80_0 = {67 65 74 5f 43 72 65 64 69 74 43 61 72 64 73 } //get_CreditCards  1
		$a_80_1 = {54 65 6c 65 67 72 61 6d 46 69 6c 65 73 } //TelegramFiles  1
		$a_80_2 = {5c 43 6f 6d 6f 64 6f 5c 44 72 61 67 6f 6e 5c 55 73 65 72 20 44 61 74 61 } //\Comodo\Dragon\User Data  1
		$a_80_3 = {5c 59 61 6e 64 65 78 5c 59 61 6e 64 65 78 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 } //\Yandex\YandexBrowser\User Data  1
		$a_80_4 = {5c 4d 61 69 6c 2e 52 75 5c 41 74 6f 6d 5c 55 73 65 72 20 44 61 74 61 } //\Mail.Ru\Atom\User Data  1
		$a_80_5 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 45 64 67 65 5c 55 73 65 72 20 44 61 74 61 } //\Microsoft\Edge\User Data  1
		$a_80_6 = {5c 43 72 79 70 74 6f 54 61 62 20 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 } //\CryptoTab Browser\User Data  1
		$a_80_7 = {73 73 66 6e 6e 61 6d 65 5c 43 6f 69 6e 6f 6d 69 5c 77 61 6c 6c 65 74 5f 64 62 } //ssfnname\Coinomi\wallet_db  1
		$a_80_8 = {5c 45 74 68 65 72 65 75 6d 5c 77 61 6c 6c 65 74 73 } //\Ethereum\wallets  1
		$a_80_9 = {41 63 63 6f 75 6e 74 49 6e 66 6f 2e 74 78 74 } //AccountInfo.txt  1
		$a_80_10 = {5c 75 73 65 72 2e 63 6f 6e 66 69 67 4e 61 6d 65 5c 45 78 6f 64 75 73 5c 65 78 6f 64 75 73 2e 77 61 6c 6c 65 74 } //\user.configName\Exodus\exodus.wallet  1
		$a_80_11 = {5c 4d 6f 6e 65 72 6f 5c 77 61 6c 6c 65 74 73 } //\Monero\wallets  1
		$a_80_12 = {43 6f 69 6e 6f 6d 69 5c 77 61 6c 6c 65 74 5f 64 62 } //Coinomi\wallet_db  1
		$a_80_13 = {52 4f 77 69 6e 64 6f 77 73 20 64 65 66 65 6e 64 65 72 20 73 75 63 6b 73 4f 54 5c 53 65 63 75 72 69 74 79 43 65 6e 74 65 77 69 6e 64 6f 77 73 20 64 65 66 65 6e 64 65 72 20 73 75 63 6b 73 72 32 } //ROwindows defender sucksOT\SecurityCentewindows defender sucksr2  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1) >=14
 
}