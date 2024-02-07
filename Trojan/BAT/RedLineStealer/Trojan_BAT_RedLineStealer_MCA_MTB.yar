
rule Trojan_BAT_RedLineStealer_MCA_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 07 90 0a 2f 00 09 20 00 01 00 00 6f 90 01 03 0a 00 09 20 80 00 00 00 6f 90 01 03 0a 00 28 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 90 02 06 20 e8 03 00 00 73 90 01 03 0a 13 05 09 11 05 09 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 00 09 11 05 09 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 00 09 17 6f 90 01 03 0a 00 08 09 6f 90 01 03 0a 17 73 90 01 03 0a 13 06 00 11 06 03 16 03 8e 69 6f 90 01 03 0a 00 11 06 6f 90 01 03 0a 00 00 de 90 00 } //01 00 
		$a_01_1 = {53 6c 65 65 70 } //01 00  Sleep
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_3 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_4 = {49 6e 76 6f 6b 65 } //01 00  Invoke
		$a_01_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_6 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_7 = {4d 6f 6e 65 73 } //01 00  Mones
		$a_01_8 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_9 = {73 65 74 5f 4b 65 79 53 69 7a 65 } //00 00  set_KeySize
	condition:
		any of ($a_*)
 
}