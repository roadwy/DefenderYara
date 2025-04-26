
rule Trojan_BAT_AsyncRat_ARS_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 00 08 06 07 6f ?? 00 00 0a 00 72 ?? 00 00 70 28 ?? 00 00 0a 00 00 de 0b 08 2c 07 08 6f ?? 00 00 0a 00 dc 72 ?? 00 00 70 28 ?? 00 00 0a 00 07 28 } //1
		$a_01_1 = {32 00 30 00 37 00 2e 00 32 00 33 00 31 00 2e 00 31 00 31 00 31 00 2e 00 34 00 38 00 } //2 207.231.111.48
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}