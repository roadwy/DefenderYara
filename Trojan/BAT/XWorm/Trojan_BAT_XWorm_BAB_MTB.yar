
rule Trojan_BAT_XWorm_BAB_MTB{
	meta:
		description = "Trojan:BAT/XWorm.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 06 07 02 07 91 03 07 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0d 09 2d da } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}