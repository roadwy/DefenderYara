
rule Trojan_BAT_Zusy_EAQH_MTB{
	meta:
		description = "Trojan:BAT/Zusy.EAQH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 00 40 01 00 8d 84 00 00 01 0a 38 09 00 00 00 03 06 16 07 6f 26 01 00 0a 02 06 16 06 8e 69 6f 27 01 00 0a 25 0b 3a e5 ff ff ff 2a } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}