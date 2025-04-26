
rule Trojan_BAT_Seraph_SPDF_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SPDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 08 91 0d 06 08 06 07 08 59 17 59 91 9c 06 07 08 59 17 59 09 9c 08 17 58 0c 08 07 18 5b 32 e0 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}