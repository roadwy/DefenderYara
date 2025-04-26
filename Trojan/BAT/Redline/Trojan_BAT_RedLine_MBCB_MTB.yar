
rule Trojan_BAT_RedLine_MBCB_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MBCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 28 ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 13 05 11 05 11 04 6f ?? 00 00 0a 11 05 18 6f ?? 00 00 0a 11 05 18 6f 7f 00 00 0a 11 05 6f ?? 00 00 0a 13 06 11 06 07 16 07 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}