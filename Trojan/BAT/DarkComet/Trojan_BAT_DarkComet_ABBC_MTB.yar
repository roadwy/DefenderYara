
rule Trojan_BAT_DarkComet_ABBC_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ABBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 11 08 91 13 04 07 11 08 17 d6 91 13 06 18 11 06 d8 08 da 11 04 da 13 07 08 11 04 da 11 06 d6 13 05 07 11 08 11 05 } //2
		$a_01_1 = {68 61 72 64 } //1 hard
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}