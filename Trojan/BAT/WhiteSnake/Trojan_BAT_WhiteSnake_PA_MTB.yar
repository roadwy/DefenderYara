
rule Trojan_BAT_WhiteSnake_PA_MTB{
	meta:
		description = "Trojan:BAT/WhiteSnake.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 00 00 fe 09 00 00 fe 0c 01 00 6f 90 01 03 0a fe 09 01 00 fe 09 02 00 28 90 01 03 0a fe 0c 01 00 fe 09 01 00 fe 09 02 00 28 90 01 03 0a 6f 90 01 03 0a 5d 6f 90 01 03 0a 61 d1 fe 0e 02 00 fe 0d 02 00 28 90 01 03 0a 28 90 01 03 0a fe 0e 00 00 fe 0c 01 00 20 01 00 00 00 58 fe 0e 01 00 fe 0c 01 00 fe 09 00 00 6f 90 01 03 0a 3f 8e ff ff ff fe 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_WhiteSnake_PA_MTB_2{
	meta:
		description = "Trojan:BAT/WhiteSnake.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 28 90 01 04 fe 09 01 00 fe 0c 02 00 fe 0c 01 00 5d 6f 90 01 04 fe 0e 03 00 72 01 00 00 70 28 90 01 04 fe 0c 00 00 fe 09 00 00 fe 0c 02 00 6f 90 01 04 fe 0c 03 00 61 d1 fe 0e 04 00 fe 0d 04 00 28 90 01 04 28 90 01 04 fe 0e 00 00 72 01 00 00 70 28 90 01 04 fe 0c 02 00 20 01 00 00 00 58 fe 0e 02 00 fe 0c 02 00 fe 09 00 00 6f 90 01 04 3f 7f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}