
rule Trojan_BAT_Remcos_BFH_MTB{
	meta:
		description = "Trojan:BAT/Remcos.BFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 8e 69 1a 2f 07 16 0b dd b8 00 00 00 20 24 67 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 0c 20 5d 66 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 0d 28 ?? 00 00 0a 13 04 11 04 08 6f ?? 00 00 0a 11 04 09 6f ?? 00 00 0a 73 1e 00 00 0a 13 05 11 05 11 04 6f ?? 00 00 0a 17 73 20 00 00 0a 13 06 11 06 06 16 06 8e 69 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a 03 11 05 6f ?? 00 00 0a 6f ?? 00 00 06 17 0b de 45 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}