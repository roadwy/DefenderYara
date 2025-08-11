
rule Trojan_BAT_Stealer_WRT_MTB{
	meta:
		description = "Trojan:BAT/Stealer.WRT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 7b 72 01 00 04 7b 6f 01 00 04 02 7b 71 01 00 04 03 6f ?? 01 00 0a 0a 02 7b 72 01 00 04 7b 6c 01 00 04 02 7b 72 01 00 04 7b 6b 01 00 04 6f ?? 01 00 0a 59 0b 07 19 fe 04 16 fe 01 0c 08 2c 39 00 02 7b 72 01 00 04 7b 6b 01 00 04 19 8d a1 00 00 01 25 16 12 00 28 1c 01 00 0a 9c 25 17 12 00 28 1d 01 00 0a 9c 25 18 12 00 28 ?? 01 00 0a 9c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}