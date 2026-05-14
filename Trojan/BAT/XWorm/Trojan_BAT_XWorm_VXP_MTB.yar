
rule Trojan_BAT_XWorm_VXP_MTB{
	meta:
		description = "Trojan:BAT/XWorm.VXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2c 05 17 13 23 2b 8e 19 2b f9 7e ff 02 00 04 2b 16 7e e1 02 00 04 fe 06 c3 05 00 06 73 06 02 00 0a 25 80 ff 02 00 04 13 0a 00 11 09 6f ?? 02 00 0a 13 0b 2b 00 2b 00 17 13 25 11 25 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}