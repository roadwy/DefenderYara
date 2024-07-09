
rule Trojan_BAT_AgentTesla_LAN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 11 05 6f ?? ?? ?? 0a 13 09 09 11 04 11 05 6f ?? ?? ?? 0a 13 0a 11 0a 28 ?? ?? ?? 0a 13 0b 08 07 11 0b 28 ?? ?? ?? 0a 9c 00 11 05 17 58 13 05 11 05 09 6f ?? ?? ?? 0a fe 04 13 0c 11 0c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}