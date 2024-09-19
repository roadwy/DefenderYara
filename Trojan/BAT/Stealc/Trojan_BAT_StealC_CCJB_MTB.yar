
rule Trojan_BAT_StealC_CCJB_MTB{
	meta:
		description = "Trojan:BAT/StealC.CCJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 08 07 08 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 00 08 07 08 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 00 73 ?? ?? ?? ?? 0d 09 08 6f ?? 00 00 0a 17 73 ?? ?? ?? ?? 13 04 11 04 02 16 02 8e 69 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 13 05 11 05 13 06 2b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}