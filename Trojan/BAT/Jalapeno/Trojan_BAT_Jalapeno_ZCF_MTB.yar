
rule Trojan_BAT_Jalapeno_ZCF_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.ZCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 8c 01 00 00 1b 03 04 6f ?? 01 00 0a 0b 11 09 1f 4c 93 20 b7 3e 00 00 59 13 06 38 5d ff ff ff 06 17 58 0a 1f 4c 0d 1f 09 13 04 1f 26 09 18 5b } //6
		$a_03_1 = {59 13 05 38 5c ff ff ff 02 28 ?? 01 00 0a 0b 11 08 1f 5c 91 20 ca 00 00 00 59 13 05 38 43 ff ff ff 02 28 ?? 00 00 0a 0b 17 13 05 38 34 ff ff ff 06 17 58 0a 20 48 01 00 00 0c 1f 0a 0d 1f 52 } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}