
rule Trojan_BAT_Snakekeylogger_AFSQ_MTB{
	meta:
		description = "Trojan:BAT/Snakekeylogger.AFSQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 02 00 "
		
	strings :
		$a_03_0 = {02 7b 02 00 00 04 06 6f 90 01 03 0a 00 00 02 7b 04 00 00 04 6f 90 01 03 0a 25 0a 14 fe 03 0c 08 90 00 } //01 00 
		$a_01_1 = {48 00 65 00 6c 00 70 00 65 00 72 00 5f 00 43 00 6c 00 61 00 73 00 73 00 65 00 73 00 } //01 00  Helper_Classes
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_4 = {52 43 32 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  RC2CryptoServiceProvider
		$a_01_5 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  MD5CryptoServiceProvider
		$a_01_6 = {62 00 61 00 63 00 6b 00 67 00 72 00 6f 00 75 00 6e 00 64 00 5f 00 6d 00 61 00 70 00 5f 00 65 00 61 00 73 00 74 00 31 00 5f 00 73 00 74 00 61 00 72 00 74 00 5f 00 31 00 2e 00 70 00 6e 00 67 00 } //00 00  background_map_east1_start_1.png
	condition:
		any of ($a_*)
 
}