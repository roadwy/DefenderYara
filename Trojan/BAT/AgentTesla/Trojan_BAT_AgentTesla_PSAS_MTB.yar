
rule Trojan_BAT_AgentTesla_PSAS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 12 05 28 10 ?? ?? ?? 07 09 18 6f 11 ?? ?? ?? 06 28 12 ?? ?? ?? 13 06 08 09 11 06 6f 13 ?? ?? ?? de 0c 11 05 2c 07 11 04 28 14 ?? ?? ?? dc 09 18 58 0d 09 07 6f 15 ?? ?? ?? 32 bd 08 6f 16 ?? ?? ?? 28 01 00 00 2b 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}