
rule Trojan_BAT_RedLineStealer_MAC_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 01 00 "
		
	strings :
		$a_03_0 = {1f 0c 8d 66 00 00 01 25 d0 d9 00 00 04 28 90 01 03 0a 0a 02 19 06 16 1f 0c 28 90 01 03 0a 02 8e 69 1f 0f 59 8d 66 00 00 01 0b 02 1f 0f 07 16 02 8e 69 1f 0f 59 28 90 01 03 0a 1f 10 8d 66 00 00 01 0c 07 8e 69 08 8e 69 59 8d 66 00 00 01 0d 07 07 8e 69 1f 10 59 08 16 1f 10 28 90 01 03 0a 07 16 09 16 07 8e 69 08 8e 69 59 28 90 01 03 0a 73 90 01 01 00 00 06 03 06 14 09 08 28 90 01 03 06 13 04 de 90 00 } //01 00 
		$a_81_1 = {53 63 61 6e 50 61 73 73 77 6f 72 64 73 } //01 00  ScanPasswords
		$a_81_2 = {53 63 61 6e 43 6f 6f 6b } //01 00  ScanCook
		$a_81_3 = {44 65 63 72 79 70 74 42 6c 6f 62 } //01 00  DecryptBlob
		$a_81_4 = {43 68 72 5f 30 5f 4d 5f 65 } //01 00  Chr_0_M_e
		$a_81_5 = {67 65 74 5f 50 6f 73 74 61 6c 43 6f 64 65 } //01 00  get_PostalCode
		$a_81_6 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_7 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_8 = {53 6c 65 65 70 } //01 00  Sleep
		$a_81_9 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_81_10 = {67 65 74 5f 6f 73 5f 63 72 79 70 74 } //01 00  get_os_crypt
		$a_81_11 = {67 65 74 5f 4b 65 79 } //01 00  get_Key
		$a_81_12 = {6d 6f 7a 5f 63 6f 6f 6b 69 65 73 } //01 00  moz_cookies
		$a_81_13 = {44 65 63 72 79 70 74 43 68 72 6f 6d 69 75 6d } //00 00  DecryptChromium
	condition:
		any of ($a_*)
 
}