
rule Trojan_BAT_XWorm_CXR_MTB{
	meta:
		description = "Trojan:BAT/XWorm.CXR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {1b 2d 24 26 28 ?? ?? ?? ?? 06 6f ?? ?? ?? ?? 28 ?? ?? ?? ?? 17 2d 13 26 07 16 07 8e 69 18 2d 0d 26 26 26 07 0c de 10 0a 2b da 0b 2b eb 28 ?? ?? ?? ?? 2b } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}