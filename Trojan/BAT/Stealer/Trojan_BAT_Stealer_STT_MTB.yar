
rule Trojan_BAT_Stealer_STT_MTB{
	meta:
		description = "Trojan:BAT/Stealer.STT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 14 0c 14 0d 14 13 04 14 13 05 00 28 ?? 00 00 0a 0d 09 14 fe 03 13 06 11 06 2c 27 09 07 6f ?? 00 00 0a 00 09 07 6f ?? 00 00 0a 00 09 6f ?? 01 00 0a 13 07 11 07 02 16 02 8e 69 6f ?? 00 00 0a 0a de 51 00 de 49 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}