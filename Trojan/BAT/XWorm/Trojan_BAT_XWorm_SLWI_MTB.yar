
rule Trojan_BAT_XWorm_SLWI_MTB{
	meta:
		description = "Trojan:BAT/XWorm.SLWI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 28 14 00 00 06 28 1d 00 00 0a 0b 1f 1a 28 1e 00 00 0a 72 ?? 00 00 70 28 1f 00 00 0a 0a 06 07 28 20 00 00 0a 28 21 00 00 0a 06 28 15 00 00 06 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}