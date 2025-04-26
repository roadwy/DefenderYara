
rule Trojan_BAT_QuasarRat_NEAA_MTB{
	meta:
		description = "Trojan:BAT/QuasarRat.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 00 06 04 28 09 00 00 2b 7d aa 00 00 04 03 06 fe 06 80 01 00 06 73 f1 00 00 0a 28 0a 00 00 2b 28 09 00 00 2b 0b } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}