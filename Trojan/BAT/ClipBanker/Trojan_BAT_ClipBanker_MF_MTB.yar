
rule Trojan_BAT_ClipBanker_MF_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 08 13 05 14 13 08 11 05 8e 69 1e 5b 13 0c 11 05 73 90 01 03 0a 73 90 01 03 06 13 0d 16 13 16 38 90 01 03 00 11 0d 6f 90 01 03 06 13 17 11 0d 6f 90 01 03 06 13 18 11 04 11 17 11 18 6f 90 01 03 0a 11 16 17 58 13 16 11 16 11 0c 3f 90 01 03 ff 11 0d 90 00 } //01 00 
		$a_01_1 = {44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 20 00 44 00 65 00 74 00 65 00 63 00 74 00 65 00 64 00 } //01 00  Debugger Detected
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_3 = {43 6f 6f 6b 69 65 43 6f 6c 6c 65 63 74 69 6f 6e } //01 00  CookieCollection
		$a_01_4 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_5 = {4c 6f 67 67 65 72 45 78 63 65 70 74 69 6f 6e } //01 00  LoggerException
		$a_01_6 = {45 76 65 6e 74 4c 6f 67 57 61 74 63 68 65 72 } //01 00  EventLogWatcher
		$a_01_7 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_8 = {2e 00 63 00 6f 00 6d 00 70 00 72 00 65 00 73 00 73 00 65 00 64 00 } //00 00  .compressed
	condition:
		any of ($a_*)
 
}