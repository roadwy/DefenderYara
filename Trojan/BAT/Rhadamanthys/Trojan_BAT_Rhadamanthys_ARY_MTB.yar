
rule Trojan_BAT_Rhadamanthys_ARY_MTB{
	meta:
		description = "Trojan:BAT/Rhadamanthys.ARY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 da 0b 16 0c 2b 15 03 08 03 08 9a 04 72 90 01 01 06 00 70 6f 90 01 01 00 00 0a a2 08 17 d6 0c 08 07 31 e7 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}