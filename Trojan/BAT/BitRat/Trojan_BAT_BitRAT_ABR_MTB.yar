
rule Trojan_BAT_BitRAT_ABR_MTB{
	meta:
		description = "Trojan:BAT/BitRAT.ABR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0a 2b 1b 00 7e 48 00 00 04 06 7e 48 00 00 04 06 91 20 c0 02 00 00 59 d2 9c 00 06 17 58 0a 06 7e 48 00 00 04 8e 69 fe 04 0b 07 2d d7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}