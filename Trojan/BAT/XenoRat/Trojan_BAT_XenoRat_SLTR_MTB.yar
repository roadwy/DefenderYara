
rule Trojan_BAT_XenoRat_SLTR_MTB{
	meta:
		description = "Trojan:BAT/XenoRat.SLTR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {7b 0f 00 00 04 2c 01 2a 02 17 7d 0f 00 00 04 72 18 02 00 70 18 73 26 00 00 0a 0a 02 06 28 5c 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}