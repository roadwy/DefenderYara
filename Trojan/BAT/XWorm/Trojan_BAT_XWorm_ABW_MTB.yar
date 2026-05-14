
rule Trojan_BAT_XWorm_ABW_MTB{
	meta:
		description = "Trojan:BAT/XWorm.ABW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 05 6f ?? 00 00 0a 13 06 06 7b ?? 00 00 04 6f ?? 00 00 0a 06 7b ?? 00 00 04 fe 04 13 07 11 07 2c 13 06 7b 73 00 00 04 12 06 28 3c 00 00 0a 6f 3d 00 00 0a 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}