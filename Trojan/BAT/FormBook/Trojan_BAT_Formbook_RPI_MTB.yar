
rule Trojan_BAT_Formbook_RPI_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 00 61 00 70 00 68 00 61 00 65 00 6c 00 6c 00 61 00 73 00 69 00 61 00 2e 00 63 00 6f 00 6d 00 } //01 00  raphaellasia.com
		$a_01_1 = {4b 00 76 00 65 00 75 00 6a 00 61 00 6d 00 72 00 2e 00 62 00 6d 00 70 00 } //01 00  Kveujamr.bmp
		$a_01_2 = {4e 00 72 00 76 00 62 00 70 00 71 00 76 00 78 00 } //01 00  Nrvbpqvx
		$a_01_3 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //01 00  get_Assembly
		$a_01_4 = {53 74 6f 70 77 61 74 63 68 } //01 00  Stopwatch
		$a_01_5 = {52 65 76 65 72 73 65 } //00 00  Reverse
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Formbook_RPI_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.RPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 00 69 00 76 00 65 00 72 00 67 00 65 00 6e 00 74 00 69 00 2e 00 74 00 65 00 63 00 68 00 2f 00 64 00 65 00 76 00 2f 00 90 02 10 2e 00 74 00 78 00 74 00 90 00 } //01 00 
		$a_01_1 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_01_2 = {57 72 69 74 65 } //01 00  Write
		$a_01_3 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_4 = {52 65 61 64 42 79 74 65 } //01 00  ReadByte
		$a_01_5 = {43 6f 6e 63 61 74 } //01 00  Concat
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_7 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_8 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_9 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //01 00  GetResponseStream
		$a_01_10 = {45 6e 63 6f 64 69 6e 67 } //01 00  Encoding
		$a_01_11 = {57 65 62 52 65 71 75 65 73 74 } //00 00  WebRequest
	condition:
		any of ($a_*)
 
}