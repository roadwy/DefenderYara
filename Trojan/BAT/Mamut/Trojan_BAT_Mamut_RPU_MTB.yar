
rule Trojan_BAT_Mamut_RPU_MTB{
	meta:
		description = "Trojan:BAT/Mamut.RPU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 7b 06 00 00 04 6f 11 00 00 0a 18 1f 64 02 7b 03 00 00 04 5b 6b 73 14 00 00 0a 6f 15 00 00 0a 26 06 17 58 0a 06 02 7b 03 00 00 04 fe 04 0b 07 2d ce } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}