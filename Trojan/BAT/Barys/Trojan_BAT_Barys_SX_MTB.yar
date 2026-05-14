
rule Trojan_BAT_Barys_SX_MTB{
	meta:
		description = "Trojan:BAT/Barys.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {05 00 70 13 04 de 60 06 16 9a 6f 46 00 00 0a 0b 06 8e 69 17 30 07 7e 47 00 00 0a 2b 03 06 17 9a 0c 02 7b 08 00 00 04 07 12 03 6f 48 00 00 0a 2c 0b } //20
		$a_80_1 = {52 41 54 20 43 6c 69 65 6e 74 } //RAT Client  10
	condition:
		((#a_01_0  & 1)*20+(#a_80_1  & 1)*10) >=30
 
}