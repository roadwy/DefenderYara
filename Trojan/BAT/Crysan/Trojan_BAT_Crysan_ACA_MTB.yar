
rule Trojan_BAT_Crysan_ACA_MTB{
	meta:
		description = "Trojan:BAT/Crysan.ACA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 1e 06 07 02 07 6f ?? 00 00 0a 03 07 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d1 9d 07 17 58 0b 07 02 6f ?? 00 00 0a fe 04 0c 08 } //3
		$a_03_1 = {0a 07 17 6f ?? 00 00 0a 0c 00 08 2d 02 2b 18 08 06 72 ?? 00 00 70 02 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 00 00 de 0b 08 2c 07 08 6f } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}