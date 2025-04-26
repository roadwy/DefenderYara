
rule Trojan_BAT_FormBook_ACHA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ACHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 07 6f ?? 00 00 0a 00 09 18 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 13 04 11 04 03 16 03 8e 69 6f ?? 00 00 0a 13 05 09 } //4
		$a_01_1 = {64 00 61 00 6f 00 4c 00 } //2 daoL
		$a_01_2 = {53 00 75 00 64 00 6f 00 6b 00 75 00 50 00 75 00 7a 00 7a 00 6c 00 65 00 } //2 SudokuPuzzle
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=9
 
}