
rule Trojan_BAT_Remcos_APWA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.APWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 04 16 94 11 04 17 94 6f ?? 00 00 0a 13 0d 11 04 16 94 1f 64 5d 16 fe 01 13 1f 11 1f 2c 2b 00 11 0a 72 ?? ?? 00 70 12 0d 28 ?? 00 00 0a 12 0d 28 ?? 00 00 0a 58 12 0d 28 ?? 00 00 0a 58 18 5d 16 fe 01 6f ?? 00 00 0a 00 00 19 8d ?? 00 00 01 13 0e 11 0e 16 12 0d 28 ?? 00 00 0a 9c 11 0e 17 12 0d 28 ?? 00 00 0a 9c 11 0e 18 12 0d 28 ?? 00 00 0a 9c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}