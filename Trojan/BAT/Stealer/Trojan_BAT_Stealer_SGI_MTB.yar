
rule Trojan_BAT_Stealer_SGI_MTB{
	meta:
		description = "Trojan:BAT/Stealer.SGI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 e6 05 00 70 28 92 00 00 0a 28 93 00 00 0a 72 20 06 00 70 28 92 00 00 0a 20 00 01 00 00 14 14 17 8d 13 00 00 01 25 16 09 6f 94 00 00 0a a2 6f 95 00 00 0a 13 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}