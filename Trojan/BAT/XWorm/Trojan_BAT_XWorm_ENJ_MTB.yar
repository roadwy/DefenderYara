
rule Trojan_BAT_XWorm_ENJ_MTB{
	meta:
		description = "Trojan:BAT/XWorm.ENJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 17 06 07 6f 25 00 00 0a 28 26 00 00 0a 1f 1e 28 12 00 00 0a 07 17 58 0b 07 06 6f 20 00 00 0a 32 e0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}