
rule Trojan_BAT_Seraph_SPYU_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SPYU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 15 31 0c 07 28 ?? ?? ?? 2b 28 02 00 00 2b 0b } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}