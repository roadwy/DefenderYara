
rule Trojan_BAT_AgentTesla_SOB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SOB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 20 ee 83 00 00 28 ?? ?? ?? 06 28 02 00 00 0a 6f 04 00 00 0a 08 6f 05 00 00 0a 0d 28 06 00 00 0a 09 07 16 07 8e 69 6f 07 00 00 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}