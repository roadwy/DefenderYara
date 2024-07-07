
rule Trojan_BAT_Lazy_PSWZ_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PSWZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 c7 00 00 70 6f 90 01 01 00 00 0a 0d 09 2c 27 09 a5 27 00 00 01 17 33 1e 08 72 c7 00 00 70 6f 90 01 01 00 00 0a 72 e5 00 00 70 72 29 01 00 70 16 1f 40 28 90 01 01 00 00 0a 26 de 0a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}