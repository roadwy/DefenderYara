
rule Trojan_BAT_Crysan_AYS_MTB{
	meta:
		description = "Trojan:BAT/Crysan.AYS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {1e 5a 0a 06 1f 40 fe 01 0b 07 2c 18 00 7e ?? 00 00 0a 7e ?? 00 00 04 28 ?? 00 00 06 80 04 00 00 04 00 2b 1f 06 1f 20 fe 01 0c 08 2c 16 } //2
		$a_03_1 = {02 03 8e 69 20 00 10 00 00 1f 40 28 ?? 00 00 06 0a 06 7e ?? 00 00 0a 28 ?? 00 00 0a 0b 07 2c 0b 28 ?? 00 00 0a 73 ?? 00 00 0a 7a 03 16 06 03 8e 69 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}