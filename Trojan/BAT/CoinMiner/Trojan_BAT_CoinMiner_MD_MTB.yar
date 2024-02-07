
rule Trojan_BAT_CoinMiner_MD_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 07 11 08 61 13 11 11 06 11 0b 11 11 20 ff 00 00 00 5f d2 9c 11 06 11 0b 17 58 11 11 20 00 ff 00 00 5f 1e 64 d2 9c 11 06 11 0b 18 58 11 11 20 00 00 ff 00 5f 1f 10 64 d2 9c 11 06 11 0b 19 58 11 11 20 00 00 00 ff 5f 1f 18 64 d2 9c 11 0a 17 58 13 0a 11 0a 11 05 3f bf fc ff ff 11 06 0d 14 13 06 09 8e 69 1e 5b 13 12 09 73 90 01 03 0a 73 90 01 03 06 13 13 16 13 14 90 00 } //01 00 
		$a_01_1 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_3 = {46 6c 75 73 68 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  FlushFinalBlock
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_5 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_6 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  CheckRemoteDebuggerPresent
		$a_01_7 = {43 72 79 70 74 6f 53 74 72 65 61 6d } //00 00  CryptoStream
	condition:
		any of ($a_*)
 
}