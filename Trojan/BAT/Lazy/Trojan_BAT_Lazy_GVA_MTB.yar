
rule Trojan_BAT_Lazy_GVA_MTB{
	meta:
		description = "Trojan:BAT/Lazy.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5b 8c 3f 00 00 01 28 2b 00 00 0a 6f 2c 00 00 0a 26 11 0e 6f 29 00 00 0a 72 73 00 00 70 28 2d 00 00 0a 2c 08 11 0e 6f 2a 00 00 0a 0d 11 0d 17 58 13 0d 11 0d 11 0c 8e 69 32 95 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}