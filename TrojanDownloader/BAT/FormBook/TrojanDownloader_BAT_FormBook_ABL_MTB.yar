
rule TrojanDownloader_BAT_FormBook_ABL_MTB{
	meta:
		description = "TrojanDownloader:BAT/FormBook.ABL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_03_0 = {1e 5b 6f 12 90 01 02 0a 6f 90 01 03 0a 07 17 6f 90 01 03 0a 06 07 6f 90 01 03 0a 17 73 90 01 03 0a 0d 16 2d ef 2b 03 0c 2b bb 09 02 16 02 8e 69 6f 90 01 03 0a de 07 09 6f 90 01 03 0a dc 06 6f 90 01 03 0a 13 04 de 4c 90 00 } //3
		$a_03_1 = {08 2b dc 6f 90 01 03 0a 2b d7 07 2b d6 90 00 } //3
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_4 = {52 66 63 32 38 39 38 44 65 72 69 76 65 42 79 74 65 73 } //1 Rfc2898DeriveBytes
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}