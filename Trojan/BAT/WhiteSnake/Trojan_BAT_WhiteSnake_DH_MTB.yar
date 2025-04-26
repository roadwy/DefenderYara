
rule Trojan_BAT_WhiteSnake_DH_MTB{
	meta:
		description = "Trojan:BAT/WhiteSnake.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 07 00 20 00 01 00 00 5d fe 0e 02 00 fe 0c 04 00 fe 0c 02 00 94 fe 0c 03 00 58 20 00 01 00 00 5d fe 0e 03 00 fe 0c 04 00 fe 0c 02 00 94 fe 0e 01 00 fe 0c 04 00 fe 0c 02 00 fe 0c 04 00 fe 0c 03 00 94 9e fe 0c 04 00 fe 0c 03 00 fe 0c 01 00 9e fe 0c 00 00 fe 09 00 00 fe 0c 07 00 ?? ?? ?? ?? ?? fe 0c 04 00 fe 0c 04 00 fe 0c 02 00 94 fe 0c 04 00 fe 0c 03 00 94 58 20 00 01 00 00 5d 94 61 d1 ?? ?? ?? ?? ?? 26 fe 0c 07 00 20 01 00 00 00 58 fe 0e 07 00 fe 0c 07 00 fe 09 00 00 ?? ?? ?? ?? ?? 3f 57 ff ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}