
rule Trojan_BAT_FormBook_AFA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 09 07 08 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 13 05 11 05 11 04 17 73 ?? 00 00 0a 13 06 11 06 06 16 06 8e 69 6f ?? 00 00 0a 11 05 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_FormBook_AFA_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0c 16 13 04 2b 1c 08 07 11 04 18 6f 52 00 00 0a 1f 10 28 53 00 00 0a 6f 54 00 00 0a 11 04 18 58 13 04 11 04 07 6f 0d 00 00 0a 32 da } //2
		$a_01_1 = {53 00 75 00 64 00 6f 00 6b 00 75 00 55 00 49 00 } //1 SudokuUI
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_FormBook_AFA_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.AFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 16 16 fe 01 13 17 11 17 2c 03 17 13 16 09 11 14 07 11 14 91 11 04 11 15 95 61 d2 9c 00 11 14 17 58 13 14 11 14 07 8e 69 fe 04 13 18 } //3
		$a_03_1 = {16 0a 16 0b 2b 11 00 02 07 06 03 04 28 ?? 00 00 06 0a 07 17 58 0b 00 07 20 00 01 00 00 fe 05 0c } //2
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}