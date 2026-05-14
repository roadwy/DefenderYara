
rule Trojan_BAT_XenoRAT_SX_MTB{
	meta:
		description = "Trojan:BAT/XenoRAT.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 1f 00 00 0a 28 2d 00 00 0a 0d 08 09 16 09 8e 69 6f 1c 00 00 0a 00 00 de 12 } //20
		$a_01_1 = {00 14 0a 1e 8d 0f 00 00 01 25 d0 26 00 00 04 28 0c 00 00 0a 0b 73 0d 00 00 0a 0c } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}