
rule Trojan_BAT_FormBook_AFA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0c 16 13 04 2b 1c 08 07 11 04 18 6f 52 00 00 0a 1f 10 28 53 00 00 0a 6f 54 00 00 0a 11 04 18 58 13 04 11 04 07 6f 0d 00 00 0a 32 da } //2
		$a_01_1 = {53 00 75 00 64 00 6f 00 6b 00 75 00 55 00 49 00 } //1 SudokuUI
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}