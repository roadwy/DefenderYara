
rule Trojan_BAT_FormBook_AOM_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AOM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 19 06 5a 6f ?? ?? ?? 0a 0b 07 1f 39 fe 02 13 09 11 09 2c 0b 07 1f 41 59 1f 0a 58 d1 0b 2b 06 07 1f 30 59 d1 0b 09 19 06 5a 17 58 6f ?? ?? ?? 0a 0c 08 1f 39 fe 02 13 0a 11 0a 2c 0b 08 1f 41 59 1f 0a 58 d1 0c 2b 06 08 1f 30 59 d1 0c 11 05 06 1f 10 07 5a 08 58 d2 9c 06 17 58 0a 06 11 04 fe 04 13 0b 11 0b 2d 98 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}