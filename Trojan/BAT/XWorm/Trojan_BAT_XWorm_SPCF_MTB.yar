
rule Trojan_BAT_XWorm_SPCF_MTB{
	meta:
		description = "Trojan:BAT/XWorm.SPCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 06 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0b 73 08 00 00 0a 0c 08 07 17 73 09 00 00 0a 0d 28 ?? ?? ?? 06 13 04 09 11 04 16 11 04 8e 69 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}