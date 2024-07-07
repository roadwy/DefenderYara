
rule Trojan_BAT_FormBook_SYU_MTB{
	meta:
		description = "Trojan:BAT/FormBook.SYU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {0d 16 07 8e 69 20 00 10 00 00 1f 40 90 01 05 13 04 08 16 09 08 8e 69 90 01 05 07 16 11 04 07 8e 69 90 01 05 09 11 04 28 02 00 00 06 6f 0f 00 00 0a de 0a 90 00 } //1
		$a_00_1 = {06 7e 01 00 00 04 72 01 00 00 70 6f 0c 00 00 0a 28 0d 00 00 0a 6f 08 00 00 06 0b 06 7e 01 00 00 04 72 2d 00 00 70 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}