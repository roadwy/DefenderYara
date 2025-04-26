
rule Trojan_BAT_AgentTesla_OM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {5d 17 d6 28 [0-04] da 0d 06 09 28 [0-04] 28 [0-04] 28 [0-04] 0a 00 08 17 d6 0c 08 07 fe ?? 16 fe ?? 13 ?? 11 ?? 2d 90 09 07 00 08 03 6f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}