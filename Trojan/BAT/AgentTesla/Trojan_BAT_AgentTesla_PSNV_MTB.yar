
rule Trojan_BAT_AgentTesla_PSNV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSNV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 0e 11 10 6f ?? ?? ?? 0a 13 11 11 11 16 16 16 16 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 2c 2a 11 04 12 11 28 ?? ?? ?? 0a 6f a1 00 00 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}