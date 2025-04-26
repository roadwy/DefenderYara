
rule Trojan_BAT_IgoogLoader_SPQ_MTB{
	meta:
		description = "Trojan:BAT/IgoogLoader.SPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 18 6f ?? ?? ?? 0a 00 06 18 6f ?? ?? ?? 0a 00 06 72 68 1d 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 0b 07 7e 18 00 00 04 16 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}