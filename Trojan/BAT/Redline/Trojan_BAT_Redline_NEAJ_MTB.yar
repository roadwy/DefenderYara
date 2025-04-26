
rule Trojan_BAT_Redline_NEAJ_MTB{
	meta:
		description = "Trojan:BAT/Redline.NEAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {2d 08 08 16 1a 28 25 00 00 0a 08 16 28 26 00 00 0a 13 04 11 04 8d 11 00 00 01 25 17 73 27 00 00 0a 13 05 06 6f 1f 00 00 0a 1b 6a 59 1a 6a 59 13 06 07 06 11 05 11 06 11 04 6a } //5
		$a_01_1 = {13 04 11 04 8e 2c 05 11 04 16 02 a2 14 11 04 6f 15 00 00 0a 13 05 11 05 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}