
rule Trojan_BAT_RedLine_KAQ_MTB{
	meta:
		description = "Trojan:BAT/RedLine.KAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 75 59 d2 81 ?? 00 00 01 02 11 09 8f ?? 00 00 01 25 71 ?? 00 00 01 1f 44 58 d2 81 ?? 00 00 01 00 11 09 17 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}