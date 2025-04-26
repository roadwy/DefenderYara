
rule Trojan_BAT_Seraph_SPXF_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SPXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 02 09 91 06 08 93 28 ?? ?? ?? 0a 61 d2 9c 08 17 58 0c 09 17 58 0d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}