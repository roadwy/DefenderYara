
rule Trojan_BAT_LgoogLoader_A_MTB{
	meta:
		description = "Trojan:BAT/LgoogLoader.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 02 09 91 07 09 04 5d 93 28 90 01 01 00 00 06 d2 6f 90 00 } //2
		$a_01_1 = {02 03 60 02 66 03 66 60 5f } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}