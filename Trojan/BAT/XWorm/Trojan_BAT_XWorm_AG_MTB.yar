
rule Trojan_BAT_XWorm_AG_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 08 75 18 00 00 1b 16 91 7e c1 00 00 04 20 b1 01 00 00 7e c1 00 00 04 20 b1 01 00 00 91 7e c1 00 00 04 20 ?? ?? 00 00 91 61 20 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}