
rule Trojan_BAT_Venomrat_MCE_MTB{
	meta:
		description = "Trojan:BAT/Venomrat.MCE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {fe 03 13 06 11 06 2c 0b 07 17 62 d2 1d 61 b4 0b 00 2b 07 00 07 17 62 d2 0b } //2
		$a_01_1 = {79 00 73 00 73 00 61 00 6a 00 77 00 6a 00 68 00 75 00 6b 00 67 00 67 00 } //1 yssajwjhukgg
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}