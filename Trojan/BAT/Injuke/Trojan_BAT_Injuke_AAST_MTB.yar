
rule Trojan_BAT_Injuke_AAST_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AAST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 13 17 2b 16 00 11 11 11 17 11 11 11 17 91 1f 20 61 d2 9c 00 11 17 17 58 13 17 11 17 11 11 8e 69 fe 04 13 18 11 18 2d dc } //2
		$a_01_1 = {11 11 11 19 11 11 11 19 91 1f 16 61 d2 9c 00 11 19 17 58 13 19 11 19 11 11 8e 69 fe 04 13 1a 11 1a 2d dc } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}