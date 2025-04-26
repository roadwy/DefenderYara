
rule Trojan_BAT_XWorm_AXM_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AXM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 39 06 07 9a 0c 1f 0a 28 ?? 00 00 0a 72 ?? 00 00 70 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 8c ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a de 03 26 de 00 07 17 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}