
rule Trojan_BAT_Fareit_OBFU_MTB{
	meta:
		description = "Trojan:BAT/Fareit.OBFU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 01 00 "
		
	strings :
		$a_00_0 = {24 34 34 39 42 42 35 37 45 2d 46 33 37 44 2d 34 32 30 37 2d 39 39 43 34 2d 35 43 43 44 41 45 44 30 42 39 35 45 } //01 00  $449BB57E-F37D-4207-99C4-5CCDAED0B95E
		$a_00_1 = {57 15 02 08 09 0a 00 00 00 00 00 00 00 00 00 00 } //01 00 
		$a_81_2 = {53 74 72 65 61 6d 52 65 61 64 65 72 } //01 00  StreamReader
		$a_81_3 = {42 69 6e 61 72 79 52 65 61 64 65 72 } //01 00  BinaryReader
		$a_81_4 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_81_5 = {41 53 43 49 49 45 6e 63 6f 64 69 6e 67 } //01 00  ASCIIEncoding
		$a_81_6 = {53 75 62 73 74 72 69 6e 67 } //01 00  Substring
		$a_81_7 = {45 6e 63 6f 64 69 6e 67 } //01 00  Encoding
		$a_81_8 = {43 6f 6e 76 65 72 74 } //01 00  Convert
		$a_81_9 = {49 6e 76 6f 6b 65 } //01 00  Invoke
		$a_81_10 = {52 61 6e 64 6f 6d } //01 00  Random
		$a_81_11 = {41 73 73 65 6d 62 6c 79 } //01 00  Assembly
		$a_81_12 = {54 68 72 65 61 64 } //01 00  Thread
		$a_81_13 = {42 69 74 43 6f 6e 76 65 72 74 65 72 } //01 00  BitConverter
		$a_81_14 = {53 74 72 69 6e 67 42 75 69 6c 64 65 72 } //00 00  StringBuilder
	condition:
		any of ($a_*)
 
}