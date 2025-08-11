
rule Trojan_BAT_Mardom_MKV_MTB{
	meta:
		description = "Trojan:BAT/Mardom.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 09 17 73 94 00 00 0a 13 05 2b 33 2b 35 16 2b 36 8e 69 2b 36 2b 3b 2b 3d 2b 42 2b 44 2b 4c 2b 51 72 ef 00 00 70 2b 51 16 2c 54 26 26 26 2b 59 72 13 01 00 70 2b 58 17 2b 5f dd c2 00 00 00 2b 5e 2b c9 2b 5e 2b c7 2b 5d 2b c6 6f ?? 00 00 0a 2b c3 11 05 2b c1 6f ?? 00 00 0a 2b bc 11 04 2b ba 6f ?? 00 00 0a 38 b2 ff ff ff 13 06 38 ad ff ff ff 11 06 38 a8 ff ff ff 03 38 a9 ff ff ff 28 ad 0a 00 06 38 a5 ff ff ff 05 38 a1 ff ff ff 6f ?? 00 00 0a 38 9e ff ff ff 0b 38 9b ff ff ff 11 05 2b 9e 06 2b 9f 06 2b a0 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}