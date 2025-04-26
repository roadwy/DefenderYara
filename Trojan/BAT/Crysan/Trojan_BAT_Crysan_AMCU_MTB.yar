
rule Trojan_BAT_Crysan_AMCU_MTB{
	meta:
		description = "Trojan:BAT/Crysan.AMCU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 6f ?? 00 00 0a 07 16 07 8e 69 6f ?? 00 00 0a 0b dd } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}