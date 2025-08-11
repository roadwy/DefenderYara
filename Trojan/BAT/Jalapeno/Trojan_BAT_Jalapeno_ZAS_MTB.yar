
rule Trojan_BAT_Jalapeno_ZAS_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.ZAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 02 11 03 11 00 11 03 91 11 04 11 03 11 04 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 20 08 00 00 00 38 ?? ff ff ff 11 03 11 00 8e 69 3c ?? ff ff ff 20 07 00 00 00 38 ?? ff ff ff 11 00 8e 69 8d ?? 00 00 01 13 02 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}