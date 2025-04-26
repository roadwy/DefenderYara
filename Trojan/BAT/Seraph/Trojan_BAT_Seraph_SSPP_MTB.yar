
rule Trojan_BAT_Seraph_SSPP_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SSPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 09 91 13 04 06 09 06 07 09 59 17 59 91 9c 06 07 09 59 17 59 11 04 9c 09 17 58 0d } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}