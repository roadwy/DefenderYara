
rule Trojan_BAT_Disstl_ABZ_MTB{
	meta:
		description = "Trojan:BAT/Disstl.ABZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0c 00 00 04 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 72 90 01 03 70 6f 90 01 03 0a 2c 2b 06 72 90 01 03 70 09 17 8d 90 01 03 01 13 04 11 04 16 1f 22 9d 11 04 6f 90 01 03 0a 1d 9a 90 0a 44 00 07 72 90 01 03 70 02 6f 90 01 03 0a 0c 28 90 01 03 0a 08 6f 3b 90 00 } //01 00 
		$a_01_1 = {43 68 65 63 6b 44 65 62 75 67 4d 6f 64 65 } //01 00  CheckDebugMode
		$a_01_2 = {43 68 65 63 6b 44 69 73 63 6f 72 64 54 6f 6b 65 6e } //01 00  CheckDiscordToken
		$a_01_3 = {43 68 65 63 6b 52 6f 62 6c 6f 78 } //01 00  CheckRoblox
		$a_01_4 = {43 68 65 63 6b 43 6f 70 69 65 64 54 65 78 74 } //01 00  CheckCopiedText
		$a_01_5 = {43 72 65 64 69 74 43 61 72 64 73 } //01 00  CreditCards
		$a_01_6 = {43 6f 6f 6b 69 65 73 } //01 00  Cookies
		$a_01_7 = {44 65 74 65 63 74 65 64 42 61 6e 6b 69 6e 67 53 65 72 76 69 63 65 73 } //01 00  DetectedBankingServices
		$a_01_8 = {43 72 65 61 74 65 44 6f 77 6e 6c 6f 61 64 4c 69 6e 6b } //01 00  CreateDownloadLink
		$a_01_9 = {47 65 74 57 69 66 69 50 61 73 73 77 6f 72 64 } //01 00  GetWifiPassword
		$a_01_10 = {53 74 65 61 6c 56 50 4e } //01 00  StealVPN
		$a_01_11 = {47 65 74 41 6c 6c 4e 65 74 77 6f 72 6b 49 6e 74 65 72 66 61 63 65 73 } //00 00  GetAllNetworkInterfaces
	condition:
		any of ($a_*)
 
}