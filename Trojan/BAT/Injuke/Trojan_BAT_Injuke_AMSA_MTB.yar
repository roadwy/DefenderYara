
rule Trojan_BAT_Injuke_AMSA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AMSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 16 0d 38 90 01 01 00 00 00 07 09 16 6f 90 01 01 00 00 0a 13 04 12 04 28 90 01 01 00 00 0a 13 05 08 11 05 6f 90 01 01 00 00 0a 09 17 58 0d 09 07 6f 90 01 01 00 00 0a 32 d8 08 6f 90 01 01 00 00 0a 13 06 dd 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}