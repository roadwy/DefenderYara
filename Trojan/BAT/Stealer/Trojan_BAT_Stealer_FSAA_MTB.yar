
rule Trojan_BAT_Stealer_FSAA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.FSAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 28 ?? 00 00 0a 04 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 07 6f ?? 00 00 0a 00 73 ?? 00 00 0a 0d 09 08 6f ?? 00 00 0a 00 09 05 6f ?? 00 00 0a 00 09 0e 04 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 03 16 03 8e 69 6f ?? 00 00 0a 13 04 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}