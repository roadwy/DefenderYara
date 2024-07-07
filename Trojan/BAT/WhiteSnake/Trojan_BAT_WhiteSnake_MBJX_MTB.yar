
rule Trojan_BAT_WhiteSnake_MBJX_MTB{
	meta:
		description = "Trojan:BAT/WhiteSnake.MBJX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 04 00 fe 0c 04 00 fe 0c 02 00 94 fe 0c 04 00 fe 0c 03 00 94 58 20 00 01 00 00 5d 94 61 d1 fe 0e 09 00 fe 0d 09 00 } //1
		$a_01_1 = {39 33 64 30 2d 65 33 31 38 33 66 66 32 61 32 36 64 } //1 93d0-e3183ff2a26d
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}