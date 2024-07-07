
rule Trojan_BAT_Azorult_SPQ_MTB{
	meta:
		description = "Trojan:BAT/Azorult.SPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 1e 11 20 18 6f 90 01 03 0a 20 03 02 00 00 28 90 01 03 0a 13 22 11 1f 11 22 6f 90 01 03 0a 00 11 20 18 58 13 20 00 11 20 11 1e 6f 90 01 03 0a fe 04 13 23 11 23 2d c7 90 00 } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}