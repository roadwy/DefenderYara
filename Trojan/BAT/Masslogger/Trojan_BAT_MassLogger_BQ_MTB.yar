
rule Trojan_BAT_MassLogger_BQ_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0e 04 03 19 8d ?? 00 00 01 25 16 12 09 28 ?? 00 00 0a 9c 25 17 } //2
		$a_03_1 = {8e 69 58 7e ?? 00 00 04 8e 69 5d 13 16 7e ?? 00 00 04 11 16 93 19 5d } //2
		$a_01_2 = {04 25 2d 17 26 7e } //1 ┄ᜭ縦
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}