
rule Trojan_BAT_AveMaria_FAT_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.FAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 2c 66 26 11 05 11 04 6f 90 01 01 00 00 0a 11 05 18 6f 90 01 01 00 00 0a 11 05 18 6f 90 01 01 00 00 0a 11 05 6f 90 01 01 00 00 0a 13 06 11 06 07 16 07 8e 69 6f 90 01 01 00 00 0a 13 07 28 90 01 01 00 00 0a 11 07 6f 90 01 01 00 00 0a 13 08 11 08 6f 90 01 01 00 00 0a 13 0a de 2d 90 00 } //3
		$a_01_1 = {68 6b 67 66 66 66 67 73 66 64 64 66 66 66 64 68 68 64 64 72 66 64 61 68 66 64 64 73 73 68 63 66 } //1 hkgfffgsfddfffdhhddrfdahfddsshcf
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}