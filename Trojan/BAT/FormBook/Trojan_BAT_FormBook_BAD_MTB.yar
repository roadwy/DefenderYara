
rule Trojan_BAT_FormBook_BAD_MTB{
	meta:
		description = "Trojan:BAT/FormBook.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {9c 13 22 16 13 23 2b 20 03 11 22 11 23 91 ?? ?? 00 00 0a 11 0f 1d 17 9c 11 09 11 22 11 23 91 58 13 09 11 23 17 58 13 23 11 23 11 21 32 da 11 15 20 f4 01 00 00 5d 2d 54 11 0f 1e 11 0f 1e 91 16 fe 01 9c 11 0f 1f 09 11 15 20 e8 03 00 00 5d 16 fe 01 9c 1f 64 09 17 58 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}