
rule Trojan_BAT_Bingoml_ABVJ_MTB{
	meta:
		description = "Trojan:BAT/Bingoml.ABVJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 1f 09 0b 02 0d 16 13 04 2b 28 09 11 04 6f 90 01 01 00 00 0a 0c 06 08 28 90 01 01 00 00 0a 07 59 28 90 01 01 00 00 0a 8c 90 01 01 00 00 01 28 90 01 01 00 00 0a 0a 11 04 17 58 13 04 11 04 09 6f 90 01 01 00 00 0a 32 ce 06 28 90 01 01 00 00 0a 0a 06 2a 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}