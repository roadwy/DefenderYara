
rule Trojan_Win32_FormBook_NF_MTB{
	meta:
		description = "Trojan:Win32/FormBook.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 52 01 66 89 06 8a 90 01 01 8d 76 02 84 c0 75 ef 5e 90 00 } //3
		$a_03_1 = {33 c0 38 01 74 0d 8d 49 00 80 7c 08 01 90 01 01 8d 40 01 75 f6 33 c9 66 90 00 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}