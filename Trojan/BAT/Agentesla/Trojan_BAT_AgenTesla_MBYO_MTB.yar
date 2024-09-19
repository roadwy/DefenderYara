
rule Trojan_BAT_AgenTesla_MBYO_MTB{
	meta:
		description = "Trojan:BAT/AgenTesla.MBYO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 06 08 6f ?? 00 00 0a 1f ?? 61 d2 9c 08 17 58 0c 08 06 6f ?? 00 00 0a 32 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}