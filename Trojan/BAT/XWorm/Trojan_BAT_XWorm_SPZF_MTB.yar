
rule Trojan_BAT_XWorm_SPZF_MTB{
	meta:
		description = "Trojan:BAT/XWorm.SPZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 08 6f ?? ?? ?? 0a 0d 12 03 28 ?? ?? ?? 0a 1f 64 fe 01 13 04 11 04 2c 0e 00 06 6f ?? ?? ?? 0a 13 05 38 dd 00 00 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}