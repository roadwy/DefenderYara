
rule Trojan_BAT_FormBook_HYL_MTB{
	meta:
		description = "Trojan:BAT/FormBook.HYL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 0d 00 00 0a 0a 02 8e 69 0b 2b 0a 00 06 02 07 91 2b 18 00 2b 0b 07 25 17 59 0b 16 fe 02 0c 2b 03 00 2b f2 08 2d 02 2b 09 2b e1 6f ?? ?? ?? 0a 2b e1 06 6f ?? ?? ?? 0a 0d 2b 00 09 2a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}