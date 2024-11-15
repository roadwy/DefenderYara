
rule Trojan_BAT_Jalapeno_AS_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 72 c9 00 00 70 15 16 28 5b 00 00 0a 0b 19 08 72 ef 00 00 70 07 19 9a 28 ?? 00 00 0a 1f 20 19 15 15 28 ?? 00 00 0a 19 07 17 9a 21 ff ff ff ff ff ff ff ff 16 28 ?? 00 00 0a 17 8d 26 00 00 01 0d 09 16 19 9e 09 28 ?? 00 00 0a 19 08 72 ef 00 00 70 07 1a 9a 28 ?? 00 00 0a 1f 20 19 15 15 28 ?? 00 00 0a 19 07 18 9a 21 ff ff ff ff ff ff ff ff 16 28 ?? 00 00 0a 17 8d 26 00 00 01 0d 09 16 19 9e 09 28 ?? 00 00 0a 08 07 19 9a 28 ?? 00 00 0a 28 ?? 00 00 0a 26 08 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}