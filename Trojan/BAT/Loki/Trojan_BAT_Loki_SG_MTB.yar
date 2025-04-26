
rule Trojan_BAT_Loki_SG_MTB{
	meta:
		description = "Trojan:BAT/Loki.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 6a 0d 2b 5b 06 17 58 20 ff 00 00 00 5f 0a 08 07 06 95 58 20 ff 00 00 00 5f 0c 07 06 95 13 04 07 06 07 08 95 9e 07 08 11 04 9e 11 07 09 d4 91 13 0e 07 06 95 07 08 95 58 d2 13 0f 11 0f d2 13 10 07 11 10 95 d2 13 11 11 05 09 d4 11 0e 6e 11 11 20 ff 00 00 00 5f 6a 61 d2 9c 09 17 6a 58 0d 09 11 05 8e 69 17 59 6a fe 02 16 fe 01 13 12 11 12 2d 92 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}