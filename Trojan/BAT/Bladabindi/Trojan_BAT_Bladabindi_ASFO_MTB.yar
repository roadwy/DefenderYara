
rule Trojan_BAT_Bladabindi_ASFO_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.ASFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8e 69 fe 04 2c 38 2b 76 08 07 08 93 0d 09 20 ff 00 00 00 5f 06 25 17 58 0a 61 1e 62 09 1e 63 06 25 17 58 0a 61 d2 60 d1 9d 18 2b 99 08 17 58 16 3a } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}