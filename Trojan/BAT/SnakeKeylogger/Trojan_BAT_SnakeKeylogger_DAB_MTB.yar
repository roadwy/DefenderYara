
rule Trojan_BAT_SnakeKeylogger_DAB_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.DAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 12 00 00 14 00 "
		
	strings :
		$a_01_0 = {57 1f a2 09 09 01 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 21 00 00 00 09 00 00 00 15 00 00 00 35 } //01 00 
		$a_01_1 = {43 61 6c 6f 72 69 65 73 43 61 6c 63 75 6c 61 74 6f 72 } //01 00  CaloriesCalculator
		$a_01_2 = {4a 61 6d 62 6f } //01 00  Jambo
		$a_01_3 = {4a 6f 67 67 69 6e 67 } //01 00  Jogging
		$a_01_4 = {53 77 69 6d 6d 69 6e 67 } //01 00  Swimming
		$a_01_5 = {50 75 6d 70 72 69 7a 65 } //14 00  Pumprize
		$a_01_6 = {57 1f b6 29 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 95 00 00 00 42 00 00 00 40 00 00 00 08 } //01 00 
		$a_01_7 = {54 72 6f 6c 6c 52 41 54 } //01 00  TrollRAT
		$a_01_8 = {67 65 74 5f 50 61 79 6c 6f 61 64 } //01 00  get_Payload
		$a_01_9 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_01_10 = {43 6f 70 79 46 72 6f 6d 53 63 72 65 65 6e } //01 00  CopyFromScreen
		$a_01_11 = {69 6e 6a 65 63 74 69 6f 6e } //14 00  injection
		$a_01_12 = {57 b5 02 1c 09 0e 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 27 00 00 00 18 00 00 00 2b 00 00 00 56 } //01 00 
		$a_01_13 = {41 45 53 5f 44 65 63 72 79 70 74 } //01 00  AES_Decrypt
		$a_01_14 = {42 6c 6f 63 6b 43 6f 70 79 } //01 00  BlockCopy
		$a_01_15 = {4c 6f 77 4e 65 74 77 6f 72 6b } //01 00  LowNetwork
		$a_01_16 = {73 74 61 72 74 75 70 49 6e 66 6f } //01 00  startupInfo
		$a_01_17 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}