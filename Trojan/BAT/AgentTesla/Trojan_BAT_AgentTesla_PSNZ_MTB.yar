
rule Trojan_BAT_AgentTesla_PSNZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSNZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 05 00 00 06 28 ?? ?? ?? 06 74 03 00 00 01 28 ?? ?? ?? 06 0a 17 8d 04 00 00 01 25 16 06 74 02 00 00 1b 28 ?? ?? ?? 06 a2 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}