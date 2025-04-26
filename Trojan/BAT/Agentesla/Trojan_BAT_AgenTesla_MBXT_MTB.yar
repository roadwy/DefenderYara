
rule Trojan_BAT_AgenTesla_MBXT_MTB{
	meta:
		description = "Trojan:BAT/AgenTesla.MBXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 08 06 09 91 9c 06 09 11 [0-01] 9c 06 08 91 06 09 91 58 20 00 01 00 00 5d } //3
		$a_01_1 = {47 43 4d 2e 65 78 65 00 4d 6f 76 65 41 6e 67 6c 65 73 00 47 43 4d 00 52 65 73 6f 6c 76 65 72 00 56 69 72 74 } //1 䍇⹍硥e潍敶湁汧獥䜀䵃刀獥汯敶r楖瑲
		$a_01_2 = {75 69 4f 41 73 68 79 75 78 67 59 55 41 } //1 uiOAshyuxgYUA
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}