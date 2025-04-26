
rule Trojan_BAT_LummaC_AMCZ_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AMCZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {5d 0c 09 06 08 91 58 20 00 01 00 00 5d 0d 06 09 91 13 07 06 09 06 08 91 9c 06 08 11 07 9c } //4
		$a_03_1 = {06 08 08 28 ?? 00 00 0a 9c 07 08 04 08 05 5d 91 9c 08 17 58 0c 08 20 00 01 00 00 3f } //1
	condition:
		((#a_01_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}