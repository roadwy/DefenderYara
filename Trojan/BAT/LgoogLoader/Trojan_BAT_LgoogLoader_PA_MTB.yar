
rule Trojan_BAT_LgoogLoader_PA_MTB{
	meta:
		description = "Trojan:BAT/LgoogLoader.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 09 06 09 93 07 09 07 8e 69 5d 93 28 90 02 04 d1 9d 00 09 17 58 0d 09 06 8e 69 fe 04 13 04 11 04 2d db 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}