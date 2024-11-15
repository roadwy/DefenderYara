
rule Trojan_BAT_Jalapeno_XRAA_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.XRAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 28 08 11 04 02 11 04 91 07 61 06 09 91 61 d2 9c 09 03 6f ?? 00 00 0a 17 59 33 04 16 0d 2b 04 09 17 58 0d 11 04 17 58 13 04 11 04 02 8e 69 32 d1 } //3
		$a_03_1 = {02 02 8e 69 17 59 91 1f 70 61 0b 02 8e 69 8d ?? 00 00 01 0c 16 0d } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}