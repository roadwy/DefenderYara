
rule Trojan_BAT_RedLineStealer_MA_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 07 11 0a 16 11 0a 8e 69 6f 90 01 03 0a 26 38 90 01 03 ff dd 90 01 04 11 07 3a 90 01 01 00 00 00 38 90 01 01 00 00 00 fe 90 01 03 45 90 02 0a 38 90 01 01 00 00 00 38 90 01 01 00 00 00 20 00 00 00 00 7e 90 01 03 04 3a 90 01 03 ff 26 20 00 00 00 00 38 90 01 03 ff 11 07 6f 90 01 03 0a 38 00 00 00 00 dc 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //01 00  FromBase64CharArray
		$a_01_2 = {65 74 61 74 53 64 61 65 52 74 65 4e 6d 65 74 73 79 53 } //01 00  etatSdaeRteNmetsyS
		$a_01_3 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_4 = {62 61 73 65 36 34 45 6e 63 6f 64 65 64 44 61 74 61 } //01 00  base64EncodedData
		$a_01_5 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_6 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}