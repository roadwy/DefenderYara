
rule Trojan_BAT_FormBook_MAAH_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MAAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 08 06 08 06 8e 69 5d 91 03 08 91 61 d2 9c 00 08 17 58 0c 08 03 8e 69 fe 04 0d 09 2d e1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}