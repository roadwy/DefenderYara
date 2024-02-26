
rule Trojan_Win32_Gomorrah_RPX_MTB{
	meta:
		description = "Trojan:Win32/Gomorrah.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 69 6c 65 5a 69 6c 6c 61 53 74 65 61 6c 65 72 } //01 00  FileZillaStealer
		$a_01_1 = {43 6f 6f 6b 69 65 73 6c 69 6e 65 43 6f 75 6e 74 } //01 00  CookieslineCount
		$a_01_2 = {63 6f 6e 74 61 63 74 5f 62 6f 74 } //01 00  contact_bot
		$a_01_3 = {4b 65 79 4c 6f 67 73 } //01 00  KeyLogs
		$a_01_4 = {75 70 6c 6f 61 64 5f 73 63 72 65 65 6e 73 68 6f 74 5f 63 32 } //01 00  upload_screenshot_c2
		$a_01_5 = {6b 65 79 6c 6f 67 5f 74 78 74 } //01 00  keylog_txt
		$a_01_6 = {47 65 74 4f 75 74 6c 6f 6f 6b 50 61 73 73 77 6f 72 64 73 } //01 00  GetOutlookPasswords
		$a_01_7 = {67 00 61 00 74 00 65 00 2e 00 70 00 68 00 70 00 } //01 00  gate.php
		$a_01_8 = {43 00 6f 00 6f 00 6b 00 69 00 65 00 73 00 5f 00 43 00 68 00 72 00 6f 00 6d 00 65 00 2e 00 74 00 78 00 74 00 } //01 00  Cookies_Chrome.txt
		$a_01_9 = {63 00 72 00 65 00 64 00 69 00 74 00 5f 00 63 00 61 00 72 00 64 00 73 00 } //00 00  credit_cards
	condition:
		any of ($a_*)
 
}