
rule Trojan_BAT_Seraph_PTGF_MTB{
	meta:
		description = "Trojan:BAT/Seraph.PTGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {38 ea fa ff ff 11 01 28 ?? 00 00 06 11 07 28 ?? 00 00 06 28 ?? 00 00 06 6f 32 00 00 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}