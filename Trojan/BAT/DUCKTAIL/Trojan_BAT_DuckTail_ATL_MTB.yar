
rule Trojan_BAT_DuckTail_ATL_MTB{
	meta:
		description = "Trojan:BAT/DuckTail.ATL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 04 1f 0f 28 ?? 00 00 2b 04 8e 69 1f 10 59 1f 0f 59 28 ?? 00 00 2b 28 ?? 00 00 2b 0b 04 04 8e 69 1f 10 59 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}