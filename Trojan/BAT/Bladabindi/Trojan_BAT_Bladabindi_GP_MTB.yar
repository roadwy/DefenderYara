
rule Trojan_BAT_Bladabindi_GP_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 0e 2d 00 fe 0c 29 00 fe 0c 29 00 1b 62 61 fe 0e 29 00 fe 0c 29 00 fe 0c 2a 00 58 fe 0e 29 00 fe 0c 29 00 fe 0c 29 00 1f 15 62 61 fe 0e 29 00 fe 0c 29 00 fe 0c 2c 00 58 fe 0e 29 00 fe 0c 29 00 fe 0c 29 00 19 64 61 fe 0e 29 00 fe 0c 29 00 fe 0c 2d 00 58 fe 0e 29 00 fe 0c 28 00 1f 15 62 fe 0c 28 00 58 fe 0c 2a 00 61 fe 0c 29 00 59 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}