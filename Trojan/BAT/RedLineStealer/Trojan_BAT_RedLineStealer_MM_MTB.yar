
rule Trojan_BAT_RedLineStealer_MM_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a fe 0e 02 00 fe 0c 02 00 20 00 01 00 00 6f 90 01 03 0a fe 0c 02 00 20 80 90 01 03 6f 90 01 03 0a 28 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 28 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 20 e8 03 00 00 73 90 01 03 0a fe 90 01 03 fe 90 01 03 fe 90 01 03 fe 90 01 03 6f 90 01 03 0a 20 08 90 01 03 5b 6f 90 01 03 0a 6f 90 01 03 0a fe 90 01 03 fe 90 01 03 fe 90 01 03 6f 90 01 03 0a 20 08 90 01 03 5b 6f 90 01 03 0a 6f 90 01 03 0a fe 0c 02 00 20 01 00 00 00 6f 28 00 00 0a fe 0c 01 00 fe 0c 02 00 6f 29 00 00 0a 20 01 00 00 00 73 2a 00 00 0a fe 0e 04 00 fe 0c 04 00 fe 09 00 00 20 00 00 00 00 fe 09 00 00 8e 69 6f 2b 00 00 0a fe 90 01 03 6f 90 01 03 0a dd 90 00 } //01 00 
		$a_81_1 = {42 55 59 20 43 52 59 50 54 20 46 52 4f 4d 20 50 55 4c 53 41 52 20 43 52 59 50 54 45 52 20 2d 20 40 50 75 6c 73 61 72 43 72 79 70 74 65 72 5f 62 6f 74 } //01 00  BUY CRYPT FROM PULSAR CRYPTER - @PulsarCrypter_bot
		$a_81_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_81_3 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_81_4 = {43 69 70 68 65 72 4d 6f 64 65 } //01 00  CipherMode
		$a_81_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_6 = {73 65 74 5f 4b 65 79 } //01 00  set_Key
		$a_81_7 = {54 6f 53 74 72 69 6e 67 } //01 00  ToString
		$a_81_8 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_81_9 = {54 6f 41 72 72 61 79 } //00 00  ToArray
	condition:
		any of ($a_*)
 
}