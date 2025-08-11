
rule Trojan_BAT_XWorm_SUBS_MTB{
	meta:
		description = "Trojan:BAT/XWorm.SUBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {12 00 12 01 28 ?? 00 00 06 02 06 07 28 ?? 00 00 06 51 28 ?? 00 00 06 0c 03 08 28 ?? 00 00 06 51 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}