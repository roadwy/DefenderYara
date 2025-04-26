
rule Trojan_BAT_XenoRAT_SPBF_MTB{
	meta:
		description = "Trojan:BAT/XenoRAT.SPBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 04 00 00 0a 0c 00 08 03 6f 05 00 00 0a 00 08 06 6f 06 00 00 0a 00 08 08 6f 07 00 00 0a 08 6f 08 00 00 0a 6f 10 00 00 0a 0d 73 0a 00 00 0a 13 04 00 11 04 09 17 73 0b 00 00 0a 13 05 00 11 05 02 16 02 8e 69 6f 0c 00 00 0a 00 11 05 6f 0d 00 00 0a 00 11 04 6f 0e 00 00 0a 0b 00 de 0d } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}