
rule Trojan_BAT_RedlineStealer_RVA_MTB{
	meta:
		description = "Trojan:BAT/RedlineStealer.RVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 01 25 16 12 02 28 ?? 00 00 0a 9c 25 17 12 02 28 ?? 00 00 0a 9c 25 18 12 02 28 ?? 00 00 0a 9c 6f ?? 00 00 0a } //2
		$a_81_1 = {61 37 66 30 66 36 31 65 2d 34 30 30 61 2d 34 63 37 36 2d 38 34 37 32 2d 63 66 32 63 31 31 34 30 66 32 36 36 } //1 a7f0f61e-400a-4c76-8472-cf2c1140f266
	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}