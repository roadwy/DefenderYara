
rule Trojan_BAT_Amadey_AMA_MTB{
	meta:
		description = "Trojan:BAT/Amadey.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 2b 06 07 28 06 00 00 06 06 6f 22 00 00 0a 25 0b 2d f0 de 0a 06 2c 06 06 6f 23 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}