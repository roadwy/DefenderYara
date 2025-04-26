
rule Trojan_BAT_FormBook_EYD_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EYD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {02 11 06 11 07 28 ?? ?? ?? 06 13 08 12 08 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 16 09 06 1a 28 ?? ?? ?? 06 00 06 1a 58 0a 00 11 07 17 58 13 07 } //1
		$a_01_1 = {45 6e 75 6d 43 61 74 65 67 6f 72 69 65 73 46 6c 61 67 73 } //1 EnumCategoriesFlags
		$a_01_2 = {44 61 74 61 4d 69 73 61 6c 69 67 6e 65 64 } //1 DataMisaligned
		$a_01_3 = {4c 6f 6e 67 50 61 74 68 44 69 72 65 63 74 6f 72 79 } //1 LongPathDirectory
		$a_01_4 = {44 69 72 65 63 74 6f 72 79 49 6e 66 6f } //1 DirectoryInfo
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}