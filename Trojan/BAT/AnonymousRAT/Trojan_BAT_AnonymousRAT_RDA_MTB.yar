
rule Trojan_BAT_AnonymousRAT_RDA_MTB{
	meta:
		description = "Trojan:BAT/AnonymousRAT.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 02 6f 2d 00 00 0a 18 8d 2f 00 00 01 25 16 1f 0a 9d 25 17 1f 0d 9d 17 6f 2e 00 00 0a 0b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}