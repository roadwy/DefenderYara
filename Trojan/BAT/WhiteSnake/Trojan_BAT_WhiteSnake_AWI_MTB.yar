
rule Trojan_BAT_WhiteSnake_AWI_MTB{
	meta:
		description = "Trojan:BAT/WhiteSnake.AWI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 09 01 00 fe 0c 02 00 fe 0c 01 00 5d 6f ?? ?? ?? 0a fe 0e 03 00 fe 0c 00 00 fe 09 00 00 fe 0c 02 00 6f ?? ?? ?? 0a fe 0c 03 00 61 d1 fe 0e 04 00 fe 0d 04 00 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}