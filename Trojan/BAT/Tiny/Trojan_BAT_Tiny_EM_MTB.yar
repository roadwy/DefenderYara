
rule Trojan_BAT_Tiny_EM_MTB{
	meta:
		description = "Trojan:BAT/Tiny.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 07 11 05 11 06 1b 58 11 04 11 06 59 20 00 10 00 00 3c 0a 00 00 00 11 04 11 06 59 38 05 00 00 00 20 00 10 00 00 16 6f 07 00 00 0a 58 13 06 11 06 11 04 3f c7 ff ff ff } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}