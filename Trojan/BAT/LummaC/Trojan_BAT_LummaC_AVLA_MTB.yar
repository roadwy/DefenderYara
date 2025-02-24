
rule Trojan_BAT_LummaC_AVLA_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AVLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 34 11 34 11 2d 11 30 91 6f ?? 00 00 0a 11 2d 11 30 11 2d 11 2f 91 9c 11 2d 11 2f 11 34 16 6f ?? 00 00 0a 9c 11 2d 11 2f 91 11 2d 11 30 91 58 28 ?? 00 00 0a 11 31 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 5d 13 35 73 ?? 00 00 0a 13 36 11 36 11 2d 11 35 91 6f ?? 00 00 0a 73 ?? 00 00 0a 11 33 6f ?? 00 00 0a 16 13 37 02 11 33 91 13 37 11 37 11 36 16 6f ?? 00 00 0a 61 d2 13 37 02 11 33 11 37 9c 11 33 17 58 13 33 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}