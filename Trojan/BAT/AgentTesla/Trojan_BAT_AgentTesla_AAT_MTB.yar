
rule Trojan_BAT_AgentTesla_AAT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1c 2d 16 26 2b 3d 16 2b 3d 8e 69 15 2d 0e 26 26 26 2b 36 2b 0e 2b 35 2b da 0b 2b e8 28 ?? ?? ?? 0a 2b ee 2a 28 ?? ?? ?? 06 2b c4 28 ?? ?? ?? 0a 2b c3 06 2b c2 6f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}