
rule Trojan_BAT_DarkTortilla_MOZ_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.MOZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_01_0 = {04 1e 5d 2c 03 03 2b 07 03 20 e2 00 00 00 61 b4 0a 2b 00 06 2a } //5
		$a_03_1 = {11 06 17 d6 13 06 11 08 14 17 8d 03 00 00 01 25 16 07 a2 6f ?? 00 00 0a 28 ?? 00 00 0a 13 09 11 09 74 43 00 00 01 13 0a 11 0a 6f ?? 00 00 0a 1f 18 9a 13 05 } //4
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}