
rule Trojan_BAT_Stealer_GFF_MTB{
	meta:
		description = "Trojan:BAT/Stealer.GFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8e 69 1a 2f 0b 16 38 95 00 00 00 dd b5 00 00 00 72 fe 01 00 70 38 8c 00 00 00 38 91 00 00 00 1a 2c 5a 72 30 02 00 70 38 8a 00 00 00 0d 73 27 00 00 0a 13 04 11 04 08 6f ?? 00 00 0a 11 04 09 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 05 72 4a 02 00 70 13 06 11 05 06 16 06 8e 69 6f ?? 00 00 0a 13 07 11 06 11 07 03 28 ?? 00 00 06 de 0c 11 04 2c 07 11 04 6f ?? 00 00 0a dc } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}