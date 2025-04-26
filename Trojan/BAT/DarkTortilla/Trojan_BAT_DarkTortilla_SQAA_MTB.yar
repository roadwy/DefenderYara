
rule Trojan_BAT_DarkTortilla_SQAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.SQAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 07 73 ?? 01 00 0a 13 04 11 04 11 07 17 73 ?? 01 00 0a 13 05 11 05 14 72 23 20 00 70 19 8d ?? 00 00 01 25 16 02 a2 25 17 16 8c ?? 00 00 01 a2 25 18 02 8e 69 } //3
		$a_03_1 = {11 05 14 72 2f 20 00 70 16 8d ?? 00 00 01 14 14 14 17 28 ?? 00 00 0a 26 11 04 6f ?? 01 00 0a 0c } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}