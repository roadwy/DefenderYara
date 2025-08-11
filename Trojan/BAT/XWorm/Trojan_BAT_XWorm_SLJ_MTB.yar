
rule Trojan_BAT_XWorm_SLJ_MTB{
	meta:
		description = "Trojan:BAT/XWorm.SLJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {1a 11 04 a2 25 1b 11 05 a2 28 ?? 00 00 0a 11 06 28 ?? 00 00 06 28 ?? 00 00 0a 13 07 11 07 28 ?? 00 00 0a 13 08 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}