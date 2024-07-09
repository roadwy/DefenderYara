
rule Trojan_BAT_lgoogLoader_MBAY_MTB{
	meta:
		description = "Trojan:BAT/lgoogLoader.MBAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 0b 07 02 16 02 8e 69 6f ?? 00 00 0a 0c 08 0d de 0b } //1
		$a_01_1 = {4c 00 4d 00 36 00 75 00 64 00 00 05 74 00 37 00 00 07 36 00 55 00 37 00 00 0d 71 00 57 00 57 00 4e 00 56 00 4a 00 00 05 69 00 72 00 00 0b 32 00 50 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}