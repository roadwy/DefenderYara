
rule Trojan_BAT_XWorm_SLWY_MTB{
	meta:
		description = "Trojan:BAT/XWorm.SLWY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 18 28 01 00 00 06 0b 07 28 02 00 00 06 0c 28 ?? 00 00 0a 72 ?? 78 04 70 28 ?? 00 00 0a 0d 09 08 28 ?? 00 00 0a 00 09 1f 1e 28 03 00 00 06 00 28 ?? 00 00 0a 72 ?? 78 04 70 28 ?? 00 00 0a 13 04 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}