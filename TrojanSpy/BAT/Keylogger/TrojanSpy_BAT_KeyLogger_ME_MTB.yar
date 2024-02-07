
rule TrojanSpy_BAT_KeyLogger_ME_MTB{
	meta:
		description = "TrojanSpy:BAT/KeyLogger.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 53 00 06 28 90 01 03 06 0b 07 17 2e 0a 07 20 01 90 01 03 fe 01 2b 01 17 0c 08 2c 33 00 7e 90 01 03 04 06 0d 12 03 fe 90 01 04 01 6f 90 01 03 0a 6f 90 01 03 0a 00 06 1f 51 fe 01 13 04 11 04 2c 0b 72 90 01 03 70 28 90 01 03 06 00 2b 13 90 00 } //01 00 
		$a_01_1 = {65 00 78 00 61 00 6d 00 70 00 6c 00 65 00 31 00 40 00 6d 00 7a 00 2e 00 6e 00 65 00 74 00 61 00 72 00 74 00 69 00 73 00 2e 00 70 00 6c 00 } //01 00  example1@mz.netartis.pl
		$a_01_2 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_3 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //01 00  CreateEncryptor
		$a_01_4 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_5 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_01_6 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_7 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //01 00  GetAsyncKeyState
		$a_01_8 = {53 6c 65 65 70 } //01 00  Sleep
		$a_01_9 = {53 65 6e 64 4d 61 69 6c } //00 00  SendMail
	condition:
		any of ($a_*)
 
}