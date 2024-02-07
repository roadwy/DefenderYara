
rule Trojan_Win32_Autorun_M_bit{
	meta:
		description = "Trojan:Win32/Autorun.M!bit,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d } //01 00  taskkill /im
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 4f 70 65 72 61 74 69 6e 67 53 79 73 74 65 6d } //01 00  SELECT * FROM Win32_OperatingSystem
		$a_01_3 = {53 45 4c 45 43 54 20 6f 72 69 67 69 6e 5f 75 72 6c 2c 20 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c 20 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 20 46 52 4f 4d 20 6c 6f 67 69 6e 73 } //01 00  SELECT origin_url, username_value, password_value FROM logins
		$a_01_4 = {42 69 74 63 6f 69 6e 5c 77 61 6c 6c 65 74 2e 64 61 74 } //01 00  Bitcoin\wallet.dat
		$a_01_5 = {73 63 72 65 65 6e 73 68 6f 74 2e 62 6d 70 } //01 00  screenshot.bmp
		$a_01_6 = {69 70 63 6f 6e 66 69 67 20 3e 69 70 63 6f 6e 66 69 67 2e 74 78 74 } //01 00  ipconfig >ipconfig.txt
		$a_01_7 = {4c 00 6f 00 63 00 61 00 6c 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 44 00 61 00 74 00 61 00 5c 00 59 00 61 00 6e 00 64 00 65 00 78 00 5c 00 59 00 61 00 6e 00 64 00 65 00 78 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 } //01 00  Local Settings\Application Data\Yandex\YandexBrowser\User Data
		$a_01_8 = {4c 00 6f 00 63 00 61 00 6c 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 44 00 61 00 74 00 61 00 5c 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 } //00 00  Local Settings\Application Data\Google\Chrome\User Data
	condition:
		any of ($a_*)
 
}