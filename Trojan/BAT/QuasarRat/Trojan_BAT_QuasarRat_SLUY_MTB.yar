
rule Trojan_BAT_QuasarRat_SLUY_MTB{
	meta:
		description = "Trojan:BAT/QuasarRat.SLUY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {da 0d 16 13 04 2b 4d 07 11 04 91 08 1b 20 88 13 00 00 6f e1 00 00 0a d8 28 92 00 00 0a 16 fe 01 13 05 11 05 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}