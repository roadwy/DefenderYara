
rule Trojan_BAT_Androm_AB_MTB{
	meta:
		description = "Trojan:BAT/Androm.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 7d 1b 00 00 04 20 2f 00 00 00 38 7d fa ff ff 7e 16 00 00 04 20 93 33 d3 d6 65 20 03 00 00 00 62 20 c7 88 e4 2f 61 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}