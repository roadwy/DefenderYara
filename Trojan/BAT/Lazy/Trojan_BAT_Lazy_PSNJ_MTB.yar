
rule Trojan_BAT_Lazy_PSNJ_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PSNJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 06 11 06 72 9f 39 01 70 06 17 14 16 13 10 12 10 6f 4b 00 00 06 26 14 13 06 00 00 00 28 70 00 00 0a 28 dd 00 00 06 72 37 3a 01 70 28 55 00 00 0a 0d 11 1d 09 6f d5 01 00 0a 13 23 11 23 2c 0c 11 1d 09 18 18 6f 4e 02 00 0a 00 00 00 de 10 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}