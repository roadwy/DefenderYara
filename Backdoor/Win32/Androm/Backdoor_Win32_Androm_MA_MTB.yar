
rule Backdoor_Win32_Androm_MA_MTB{
	meta:
		description = "Backdoor:Win32/Androm.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {51 51 53 55 56 57 8b f9 33 c9 8b 47 3c 8b 44 38 78 03 c7 8b 50 20 8b 58 1c 03 d7 8b 68 24 03 df 8b 40 18 03 ef 89 54 24 14 89 44 24 10 85 c0 74 } //01 00 
		$a_01_1 = {77 61 6c 6c 65 74 2e 64 61 74 } //01 00  wallet.dat
		$a_01_2 = {5c 45 78 6f 64 75 73 5c 65 78 6f 64 75 73 2e 77 61 6c 6c 65 74 5c } //01 00  \Exodus\exodus.wallet\
		$a_01_3 = {5c 59 61 6e 64 65 78 5c 59 61 6e 64 65 78 42 72 6f 77 73 65 72 5c } //01 00  \Yandex\YandexBrowser\
		$a_01_4 = {43 6f 6f 6b 69 65 73 4f 70 65 72 61 } //01 00  CookiesOpera
		$a_01_5 = {53 63 72 65 65 6e 73 68 6f 74 } //00 00  Screenshot
	condition:
		any of ($a_*)
 
}