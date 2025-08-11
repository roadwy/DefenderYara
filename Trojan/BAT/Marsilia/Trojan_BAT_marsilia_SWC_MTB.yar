
rule Trojan_BAT_marsilia_SWC_MTB{
	meta:
		description = "Trojan:BAT/marsilia.SWC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {1e 8d 09 00 00 01 0c 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 09 16 08 16 1e 28 ?? 00 00 0a 06 08 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 6f ?? 00 00 0a 13 04 02 28 ?? 00 00 0a 13 05 11 04 11 05 16 11 05 8e 69 6f ?? 00 00 0a 13 06 28 ?? 00 00 0a 11 06 6f ?? 00 00 0a 13 07 dd 0d 00 00 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}