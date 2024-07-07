
rule Trojan_BAT_Lazy_SPH_MTB{
	meta:
		description = "Trojan:BAT/Lazy.SPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 72 85 00 00 70 6f 90 01 03 0a 13 05 de 1a 6f 90 01 03 0a 72 c9 00 00 70 16 28 90 01 03 0a 17 33 05 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}