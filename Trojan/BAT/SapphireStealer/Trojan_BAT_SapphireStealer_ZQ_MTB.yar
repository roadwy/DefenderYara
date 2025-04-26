
rule Trojan_BAT_SapphireStealer_ZQ_MTB{
	meta:
		description = "Trojan:BAT/SapphireStealer.ZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_81_0 = {53 61 70 70 68 69 72 65 5c 6f 62 6a 5c } //1 Sapphire\obj\
		$a_81_1 = {5b 45 52 52 4f 52 5f 47 45 54 53 45 43 52 45 54 4b 45 59 5f 4d 45 54 48 4f 44 5d } //1 [ERROR_GETSECRETKEY_METHOD]
		$a_81_2 = {5b 45 52 52 4f 52 5f 43 41 4e 54 5f 47 45 54 5f 50 41 53 53 57 4f 52 44 5d } //1 [ERROR_CANT_GET_PASSWORD]
		$a_81_3 = {54 65 6c 65 67 72 61 6d 2b 3c 53 65 6e 64 4c 6f 67 73 3e 64 5f 5f 30 } //1 Telegram+<SendLogs>d__0
		$a_81_4 = {5b 45 52 52 4f 52 5d 20 63 61 6e 27 74 20 63 72 65 61 74 65 20 77 6f 72 6b 20 64 69 72 65 63 74 6f 72 79 } //1 [ERROR] can't create work directory
		$a_81_5 = {59 61 6e 64 65 78 5c 59 61 6e 64 65 78 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 } //1 Yandex\YandexBrowser\User Data
		$a_81_6 = {42 72 61 76 65 53 6f 66 74 77 61 72 65 5c 42 72 61 76 65 2d 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 } //1 BraveSoftware\Brave-Browser\User Data
		$a_81_7 = {63 6f 6f 6b 69 65 73 2e 6a 73 6f 6e } //1 cookies.json
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=5
 
}