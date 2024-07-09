
rule Trojan_BAT_Androm_ABXY_MTB{
	meta:
		description = "Trojan:BAT/Androm.ABXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 2c 04 2b 1c 2b 21 7e ?? 00 00 04 7e ?? 00 00 04 2b 18 2b 1d 2b 1e 2b 23 75 ?? 00 00 1b 2b 23 2a 28 ?? 00 00 06 2b dd 0a 2b dc 28 ?? 00 00 06 2b e1 06 2b e0 28 ?? 00 00 06 2b db 28 ?? 00 00 06 2b d6 28 ?? 00 00 06 2b d6 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}