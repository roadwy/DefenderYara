
rule Trojan_BAT_FormBook_AMK_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 06 2b 21 11 06 1c 5d 16 fe 01 13 07 11 07 2c 0d 06 11 06 06 11 06 91 1f 3d 61 b4 9c 00 00 11 06 17 d6 13 06 11 06 11 05 31 d9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}