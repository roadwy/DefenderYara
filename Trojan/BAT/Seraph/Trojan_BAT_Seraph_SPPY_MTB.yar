
rule Trojan_BAT_Seraph_SPPY_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SPPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {38 00 00 00 00 11 09 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 13 09 20 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}