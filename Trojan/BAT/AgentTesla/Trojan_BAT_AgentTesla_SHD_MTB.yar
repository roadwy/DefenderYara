
rule Trojan_BAT_AgentTesla_SHD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 71 04 00 06 0a 09 06 6f ?? ?? ?? 0a 16 06 6f ?? ?? ?? 0a 8e 69 6f 6c 05 00 0a 06 6f ?? ?? ?? 0a 08 13 05 de 0e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}