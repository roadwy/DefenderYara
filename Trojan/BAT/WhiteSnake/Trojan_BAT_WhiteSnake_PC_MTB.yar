
rule Trojan_BAT_WhiteSnake_PC_MTB{
	meta:
		description = "Trojan:BAT/WhiteSnake.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 09 00 00 fe 0c 02 00 6f 90 01 04 fe 0e 03 00 72 90 01 04 28 90 01 04 fe 0c 00 00 fe 0c 02 00 fe 0c 00 00 6f 90 01 04 5d 6f 90 01 04 fe 0e 04 00 fe 0c 01 00 fe 0c 03 00 fe 0c 04 00 61 d1 fe 0e 05 00 fe 0d 05 00 28 90 01 04 28 90 01 04 fe 0e 01 00 fe 0c 02 00 20 01 00 00 00 58 fe 0e 02 00 fe 0c 02 00 fe 09 00 00 6f 90 01 04 3f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}