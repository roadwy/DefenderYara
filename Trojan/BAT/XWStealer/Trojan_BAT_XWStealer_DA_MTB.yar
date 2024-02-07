
rule Trojan_BAT_XWStealer_DA_MTB{
	meta:
		description = "Trojan:BAT/XWStealer.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 57 6f 72 6d } //01 00  XWorm
		$a_01_1 = {4f 66 66 6c 69 6e 65 4b 65 79 6c 6f 67 67 65 72 } //01 00  OfflineKeylogger
		$a_01_2 = {61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 } //01 00  api.telegram.org/bot
		$a_01_3 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 41 6e 74 69 76 69 72 75 73 50 72 6f 64 75 63 74 } //01 00  Select * from AntivirusProduct
		$a_01_4 = {2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 } //00 00  -ExecutionPolicy Bypass
	condition:
		any of ($a_*)
 
}