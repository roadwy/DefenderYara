
rule Trojan_BAT_Seraph_AMBC_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AMBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 07 11 05 11 07 28 ?? ?? 00 06 20 ?? ?? 00 00 61 d1 9d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}