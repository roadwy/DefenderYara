
rule Trojan_BAT_MassloggerRAT_SYDF_MTB{
	meta:
		description = "Trojan:BAT/MassloggerRAT.SYDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 00 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 06 08 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 0d 09 02 16 02 8e 69 6f ?? 00 00 0a 13 04 de 16 07 2c 07 07 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}