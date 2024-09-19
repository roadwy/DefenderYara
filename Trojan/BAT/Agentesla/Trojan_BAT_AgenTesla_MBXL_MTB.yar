
rule Trojan_BAT_AgenTesla_MBXL_MTB{
	meta:
		description = "Trojan:BAT/AgenTesla.MBXL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {04 05 5d 05 58 05 5d 0a 03 06 91 0b 07 0e ?? 61 0c 08 0e ?? 59 20 00 } //1
		$a_01_1 = {35 00 41 00 58 00 42 00 4a 00 5a 00 37 00 38 00 48 00 38 00 35 00 37 00 59 00 35 00 34 00 44 00 37 00 37 00 58 00 4a 00 50 00 38 00 } //1 5AXBJZ78H857Y54D77XJP8
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}