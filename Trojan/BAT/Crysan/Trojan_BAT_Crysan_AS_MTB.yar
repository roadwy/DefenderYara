
rule Trojan_BAT_Crysan_AS_MTB{
	meta:
		description = "Trojan:BAT/Crysan.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 02 8e 69 28 d5 90 01 02 06 90 0a 0c 00 11 04 02 90 00 } //01 00 
		$a_03_1 = {fe 09 00 00 fe 09 90 01 01 00 7e c9 90 01 02 04 28 33 90 01 02 06 20 01 90 01 02 00 28 c0 90 01 02 06 3a a6 90 01 02 ff 26 38 9c 90 01 02 ff 38 1f 90 01 02 00 20 02 90 01 02 00 38 91 90 01 02 ff 20 00 90 01 02 00 28 86 90 01 01 00 06 90 00 } //01 00 
		$a_01_2 = {41 65 73 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  AesCryptoServiceProvider
		$a_01_3 = {52 65 61 64 42 79 74 65 73 } //01 00  ReadBytes
		$a_01_4 = {44 65 6c 65 67 61 74 65 } //01 00  Delegate
		$a_01_5 = {54 72 69 6d } //01 00  Trim
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_7 = {45 6e 63 6f 64 69 6e 67 } //01 00  Encoding
		$a_01_8 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_9 = {46 6c 75 73 68 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  FlushFinalBlock
		$a_01_10 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_01_11 = {67 65 74 5f 45 78 65 63 75 74 61 62 6c 65 50 61 74 68 } //01 00  get_ExecutablePath
		$a_01_12 = {52 65 61 64 41 6c 6c 54 65 78 74 } //00 00  ReadAllText
	condition:
		any of ($a_*)
 
}