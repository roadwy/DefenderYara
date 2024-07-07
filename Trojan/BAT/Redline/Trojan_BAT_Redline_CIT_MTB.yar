
rule Trojan_BAT_Redline_CIT_MTB{
	meta:
		description = "Trojan:BAT/Redline.CIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 0d 00 00 06 74 1e 00 00 01 72 12 01 00 70 20 00 01 00 00 14 14 14 6f 1c 00 00 0a } //10
		$a_01_1 = {28 19 00 00 06 28 1d 00 00 0a 72 2c 01 00 70 28 1a 00 00 06 13 01 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}