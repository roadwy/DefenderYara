
rule Trojan_BAT_ZgRat_SGB_MTB{
	meta:
		description = "Trojan:BAT/ZgRat.SGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 72 01 00 00 70 28 0f 00 00 06 80 01 00 00 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}