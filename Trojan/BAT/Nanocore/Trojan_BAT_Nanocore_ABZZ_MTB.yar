
rule Trojan_BAT_Nanocore_ABZZ_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 11 0a 11 09 6f ?? 00 00 0a 13 0b 16 13 0c 11 05 11 08 9a 13 0e 11 0e 13 0d 11 0d 72 b7 09 00 70 28 ?? 00 00 0a 2d 1e 11 0d 72 bb 09 00 70 28 ?? 00 00 0a 2d 1b 11 0d 72 bf 09 00 70 28 ?? 00 00 0a 2d 18 2b 21 12 0b 28 ?? 00 00 0a 13 0c 2b 16 12 0b 28 ?? 00 00 0a 13 0c 2b 0b 12 0b 28 ?? 00 00 0a 13 0c 2b 00 07 11 0c 6f ?? 00 00 0a 00 00 11 0a 17 58 13 0a 11 0a 09 fe 04 13 0f 11 0f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}