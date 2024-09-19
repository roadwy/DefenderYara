
rule Trojan_BAT_LummaC_AMAJ_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AMAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 5d 91 13 ?? 11 ?? 08 20 00 01 00 00 5d 58 11 ?? 58 20 00 01 00 00 5d 13 ?? 11 ?? 11 ?? 19 5a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 } //2
		$a_01_1 = {5a 20 00 01 00 00 5d d2 0c 06 07 08 9c 00 07 17 58 0b } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}