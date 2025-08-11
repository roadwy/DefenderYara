
rule Trojan_BAT_Jalapeno_MKG_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.MKG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 00 8e 69 1a 3f b9 00 00 00 20 05 00 00 00 38 ba ff ff ff 72 4c 03 00 70 28 ?? 00 00 0a 13 09 20 08 00 00 00 38 a4 ff ff ff 28 ?? 00 00 0a 13 0b 20 02 00 00 00 38 93 ff ff ff 72 a6 03 00 70 28 ?? 00 00 0a 13 0e 20 01 00 00 00 7e 94 01 00 04 7b ae 01 00 04 3a 73 ff ff ff } //5
		$a_03_1 = {11 05 11 0b 6f ?? 00 00 0a 17 73 23 00 00 0a 13 0c 20 00 00 00 00 7e 94 01 00 04 7b 6d 01 00 04 39 0f 00 00 00 26 20 00 00 00 00 38 04 00 00 00 fe 0c 0d 00 } //4
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}