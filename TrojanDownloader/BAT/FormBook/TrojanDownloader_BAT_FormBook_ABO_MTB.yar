
rule TrojanDownloader_BAT_FormBook_ABO_MTB{
	meta:
		description = "TrojanDownloader:BAT/FormBook.ABO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 08 07 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 07 17 6f 90 01 03 0a 06 07 6f 90 01 03 0a 17 73 90 01 03 0a 0d 16 2d 0e 16 2d 0b 09 02 16 02 8e 69 6f 90 01 03 0a de 0d 1d 2c 03 09 2c 06 09 6f 90 01 03 0a dc 06 6f 90 01 03 0a 13 04 16 90 00 } //4
		$a_03_1 = {08 2b df 6f 90 01 03 0a 2b da 08 2b dc 6f 90 01 03 0a 2b d7 90 00 } //3
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {52 66 63 32 38 39 38 44 65 72 69 76 65 42 79 74 65 73 } //1 Rfc2898DeriveBytes
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=9
 
}