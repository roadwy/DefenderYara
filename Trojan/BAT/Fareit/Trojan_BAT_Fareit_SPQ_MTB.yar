
rule Trojan_BAT_Fareit_SPQ_MTB{
	meta:
		description = "Trojan:BAT/Fareit.SPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 06 00 00 01 0a 06 25 0c 2c 05 08 8e 69 2d 05 16 e0 0b 2b 09 08 16 8f 06 00 00 01 e0 0b 07 02 54 14 0c 03 0d 09 2c 06 06 28 90 01 03 0a 06 13 04 11 04 2a 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}