
rule Trojan_BAT_FormBook_AGD_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 16 13 07 2b 41 08 11 07 72 0f 0e 00 70 28 90 01 03 0a 72 2d 0e 00 70 20 00 01 00 00 14 14 18 8d 1e 00 00 01 25 16 07 11 07 9a a2 25 17 1f 10 90 00 } //2
		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 31 00 } //1 WindowsFormsApp1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}