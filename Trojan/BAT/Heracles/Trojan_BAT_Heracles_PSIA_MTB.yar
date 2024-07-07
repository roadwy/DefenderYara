
rule Trojan_BAT_Heracles_PSIA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PSIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 01 28 0b 00 00 06 11 02 6f 90 01 03 0a 20 03 00 00 00 7e 22 00 00 04 7b 29 00 00 04 3a 90 01 03 ff 26 20 02 00 00 00 38 90 01 03 ff 11 04 28 0a 00 00 06 13 01 20 00 00 00 00 7e 22 00 00 04 7b 4e 00 00 04 39 90 01 03 ff 26 20 00 00 00 00 38 90 01 03 ff 02 28 05 00 00 0a 74 0b 00 00 01 13 04 38 90 01 03 ff 73 06 00 00 0a 13 02 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}