
rule Trojan_BAT_LgoogLoader_CBT_MTB{
	meta:
		description = "Trojan:BAT/LgoogLoader.CBT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 07 6f 20 00 00 0a 07 6f 90 01 04 6f 90 01 04 0c 03 73 90 01 04 0d 09 08 16 73 90 01 04 13 04 00 03 8e 69 8d 90 01 04 13 05 11 04 11 05 16 11 05 8e 69 6f 90 01 04 13 06 11 05 11 06 28 90 01 04 28 90 01 04 13 07 de 2e 11 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}