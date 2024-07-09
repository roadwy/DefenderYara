
rule Trojan_BAT_AgentTesla_PSAU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 12 05 28 1b ?? ?? ?? 07 09 18 6f 1c ?? ?? ?? 06 28 1d ?? ?? ?? 13 06 08 09 11 06 6f 1e ?? ?? ?? de 0c 11 05 2c 07 11 04 28 1f ?? ?? ?? dc 09 18 58 0d 09 07 6f 20 ?? ?? ?? 32 bd 08 6f 21 ?? ?? ?? 28 01 00 00 2b } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}