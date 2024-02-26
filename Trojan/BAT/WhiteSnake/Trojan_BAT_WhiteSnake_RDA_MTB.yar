
rule Trojan_BAT_WhiteSnake_RDA_MTB{
	meta:
		description = "Trojan:BAT/WhiteSnake.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {fe 0c 04 00 fe 0c 04 00 fe 0c 02 00 94 fe 0c 04 00 fe 0c 03 00 94 58 20 00 01 00 00 5d 94 61 d1 fe 0e 09 00 fe 0d 09 00 } //00 00 
	condition:
		any of ($a_*)
 
}