
rule Trojan_BAT_Stealer_AGWA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.AGWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 c0 0f 00 00 28 ?? 00 00 0a 00 73 ?? 00 00 0a 0a 06 72 ?? 00 00 70 6f ?? 00 00 0a 0b 16 0c 2b 13 00 07 08 07 08 91 20 ?? ?? 00 00 59 d2 9c 08 17 58 0c 00 08 07 8e 69 fe 04 0d 09 2d e3 28 ?? 00 00 0a 07 6f ?? 00 00 0a 13 04 2b 00 11 04 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}