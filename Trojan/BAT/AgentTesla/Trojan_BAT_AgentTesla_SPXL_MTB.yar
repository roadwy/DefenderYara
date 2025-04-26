
rule Trojan_BAT_AgentTesla_SPXL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPXL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 07 09 07 8e 69 5d 91 02 09 91 61 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 00 09 17 58 0d 09 02 8e 69 fe 04 13 04 11 04 2d d7 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}