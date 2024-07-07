
rule Trojan_BAT_Bladabindi_CWAA_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.CWAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 2d 02 08 6f 90 01 01 00 00 0a 03 08 03 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a 61 0d 07 72 90 01 02 00 70 09 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 26 08 17 58 0c 08 02 6f 90 01 01 00 00 0a 32 ca 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}