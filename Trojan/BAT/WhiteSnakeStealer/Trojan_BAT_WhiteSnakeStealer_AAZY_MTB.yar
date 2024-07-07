
rule Trojan_BAT_WhiteSnakeStealer_AAZY_MTB{
	meta:
		description = "Trojan:BAT/WhiteSnakeStealer.AAZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 00 00 00 00 fe 0e 06 00 38 90 01 01 00 00 00 fe 0c 03 00 fe 0c 06 00 fe 09 00 00 fe 0c 06 00 6f 90 01 01 00 00 0a fe 0c 02 00 fe 0c 06 00 fe 0c 02 00 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a 61 d1 9d fe 0c 06 00 20 01 00 00 00 58 fe 0e 06 00 fe 0c 06 00 fe 09 00 00 6f 90 01 01 00 00 0a 3f b1 ff ff ff 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}