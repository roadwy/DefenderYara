
rule Trojan_BAT_XWorm_PLIVH_MTB{
	meta:
		description = "Trojan:BAT/XWorm.PLIVH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 04 02 11 04 17 62 6f ?? 00 00 0a 28 ?? 00 00 06 1a 62 02 11 04 17 62 17 58 6f ?? 00 00 0a 28 ?? 00 00 06 58 d2 9c 11 04 17 58 13 04 11 04 06 17 63 32 cb } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}