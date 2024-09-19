
rule Trojan_BAT_XWorm_SPXF_MTB{
	meta:
		description = "Trojan:BAT/XWorm.SPXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 23 2b 28 2b 2d 09 08 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 0a de 0a } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}