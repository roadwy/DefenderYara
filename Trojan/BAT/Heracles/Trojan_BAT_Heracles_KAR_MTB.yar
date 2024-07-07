
rule Trojan_BAT_Heracles_KAR_MTB{
	meta:
		description = "Trojan:BAT/Heracles.KAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 08 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 0d 07 09 06 08 18 5b 06 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a 61 d1 8c 90 01 01 00 00 01 28 90 01 01 00 00 0a 0b 08 18 58 0c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}