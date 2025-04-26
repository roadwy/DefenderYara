
rule Trojan_BAT_LgoogLoader_MBS_MTB{
	meta:
		description = "Trojan:BAT/LgoogLoader.MBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 00 06 7e ?? 00 00 04 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 0b 02 28 ?? 00 00 0a 0c 07 08 16 08 8e 69 6f ?? 00 00 0a 0d 09 13 04 de } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}