
rule Trojan_BAT_Seraph_SPCX_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SPCX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 73 36 00 00 0a 28 ?? ?? ?? 0a 0c 08 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0d 09 06 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 13 04 11 04 13 07 de 0a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}