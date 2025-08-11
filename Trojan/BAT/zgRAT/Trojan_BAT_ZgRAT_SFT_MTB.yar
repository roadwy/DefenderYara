
rule Trojan_BAT_ZgRAT_SFT_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.SFT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 06 6f ?? 00 00 0a 11 04 08 6f ?? 00 00 0a 11 04 11 04 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 6f ?? 00 00 0a 13 05 73 ?? 00 00 0a 13 06 11 06 11 05 17 73 ?? 00 00 0a 13 07 11 07 02 16 02 8e 69 6f ?? 00 00 0a 11 07 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a 13 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}