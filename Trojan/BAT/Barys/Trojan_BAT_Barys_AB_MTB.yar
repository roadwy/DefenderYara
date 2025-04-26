
rule Trojan_BAT_Barys_AB_MTB{
	meta:
		description = "Trojan:BAT/Barys.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 03 2a 11 02 18 58 13 02 20 01 00 00 00 7e 6a 00 00 04 7b 0a 00 00 04 3a 92 ff ff ff 26 20 01 00 00 00 38 87 ff ff ff 11 03 11 02 18 5b 02 11 02 18 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}