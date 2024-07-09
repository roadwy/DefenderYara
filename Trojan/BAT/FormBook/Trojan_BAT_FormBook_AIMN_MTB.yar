
rule Trojan_BAT_FormBook_AIMN_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AIMN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 16 13 08 2b 1d 07 06 11 08 9a 1f 10 28 ?? ?? ?? 0a 8c 56 00 00 01 6f ?? ?? ?? 0a 26 11 08 17 58 13 08 11 08 06 8e 69 } //2
		$a_01_1 = {42 00 69 00 62 00 6c 00 69 00 6f 00 74 00 65 00 63 00 61 00 } //1 Biblioteca
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}