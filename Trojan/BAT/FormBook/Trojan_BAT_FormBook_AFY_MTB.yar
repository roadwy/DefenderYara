
rule Trojan_BAT_FormBook_AFY_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AFY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 13 04 2b 1f 00 08 07 11 04 18 6f fe 00 00 0a 1f 10 28 ff 00 00 0a 6f 00 01 00 0a 00 00 11 04 18 58 13 04 11 04 07 6f 24 00 00 0a fe 04 13 05 11 05 2d d1 } //2
		$a_01_1 = {53 00 75 00 64 00 6f 00 6b 00 75 00 } //1 Sudoku
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}