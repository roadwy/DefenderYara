
rule Trojan_BAT_Injector_SXB_MTB{
	meta:
		description = "Trojan:BAT/Injector.SXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 7b 3d 00 00 0a 6f ?? 00 00 0a 03 02 28 ?? 00 00 0a 6f ?? 00 00 0a 13 04 11 04 04 6f ?? 00 00 0a 0a 00 de 08 } //30
		$a_03_1 = {16 0a 02 28 ?? 00 00 0a 7e ?? 00 00 0a 28 ?? 00 00 0a 0b 07 2c 05 00 06 0c 2b 42 02 28 ?? 00 00 0a 0d 09 2c 05 } //10
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*10) >=40
 
}