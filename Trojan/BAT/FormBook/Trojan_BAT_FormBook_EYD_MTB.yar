
rule Trojan_BAT_FormBook_EYD_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EYD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 11 06 11 07 28 90 01 03 06 13 08 12 08 28 90 01 03 0a 28 90 01 03 06 16 09 06 1a 28 90 01 03 06 00 06 1a 58 0a 00 11 07 17 58 13 07 90 00 } //01 00 
		$a_01_1 = {45 6e 75 6d 43 61 74 65 67 6f 72 69 65 73 46 6c 61 67 73 } //01 00  EnumCategoriesFlags
		$a_01_2 = {44 61 74 61 4d 69 73 61 6c 69 67 6e 65 64 } //01 00  DataMisaligned
		$a_01_3 = {4c 6f 6e 67 50 61 74 68 44 69 72 65 63 74 6f 72 79 } //01 00  LongPathDirectory
		$a_01_4 = {44 69 72 65 63 74 6f 72 79 49 6e 66 6f } //00 00  DirectoryInfo
	condition:
		any of ($a_*)
 
}