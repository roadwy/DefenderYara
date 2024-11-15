
rule Trojan_BAT_Nanocore_AMA_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 13 04 11 04 06 11 04 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 11 04 06 11 04 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 08 11 04 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 05 11 05 02 16 02 8e 69 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 07 6f ?? 00 00 0a 13 06 de 11 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}