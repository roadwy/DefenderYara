
rule Trojan_BAT_Heracles_EANT_MTB{
	meta:
		description = "Trojan:BAT/Heracles.EANT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 06 72 a5 01 00 70 7e 1d 00 00 04 16 72 a5 01 00 70 28 6f 00 00 0a 6f 70 00 00 0a 28 71 00 00 0a 28 72 00 00 0a 6f 73 00 00 0a 00 00 08 17 58 0c 08 07 fe 02 16 fe 01 0d 09 2d c4 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}