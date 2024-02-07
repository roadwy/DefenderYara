
rule Trojan_BAT_SnakeKeylogger_ABW_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ABW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 10 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 14 72 85 90 01 02 70 6f 40 90 01 02 0a 0b 72 87 90 01 02 70 0c 06 28 23 90 01 02 0a 28 21 90 01 02 0a 00 08 28 23 90 01 02 0a 28 21 90 01 02 0a 00 07 72 b5 90 01 02 70 6f 55 90 01 02 0a 28 21 90 01 02 0a 00 07 72 9d 90 01 02 70 6f 45 90 01 02 0a 28 21 90 01 02 0a 00 08 28 2f 90 01 02 0a 0d 09 28 21 90 01 02 06 13 04 72 c5 90 01 02 70 07 72 f3 90 01 02 70 28 44 90 01 02 0a 13 05 08 90 0a 7b 00 02 6f ea 90 01 02 06 6f 06 90 01 02 06 0a 90 00 } //01 00 
		$a_01_1 = {44 61 74 65 54 69 6d 65 } //01 00  DateTime
		$a_01_2 = {67 65 74 5f 53 63 72 69 70 74 54 69 6d 65 } //01 00  get_ScriptTime
		$a_01_3 = {47 65 74 43 73 4d 65 74 61 64 61 74 61 50 61 74 68 } //01 00  GetCsMetadataPath
		$a_01_4 = {47 65 74 44 65 73 74 69 6e 61 74 69 6f 6e 46 69 6c 65 50 61 74 68 } //01 00  GetDestinationFilePath
		$a_01_5 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_6 = {49 43 72 79 70 74 6f 54 72 61 6e 73 66 6f 72 6d } //01 00  ICryptoTransform
		$a_01_7 = {47 65 74 44 6f 6d 61 69 6e } //01 00  GetDomain
		$a_01_8 = {57 72 69 74 65 41 6c 6c 54 65 78 74 57 69 74 68 42 61 63 6b 75 70 } //01 00  WriteAllTextWithBackup
		$a_01_9 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_01_10 = {52 43 32 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  RC2CryptoServiceProvider
		$a_01_11 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_12 = {4c 6f 67 44 69 72 65 63 74 6f 72 69 65 73 } //01 00  LogDirectories
		$a_01_13 = {52 65 61 64 41 6c 6c 54 65 78 74 } //01 00  ReadAllText
		$a_01_14 = {57 72 69 74 65 41 6c 6c 54 65 78 74 } //01 00  WriteAllText
		$a_01_15 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //00 00  get_Assembly
	condition:
		any of ($a_*)
 
}