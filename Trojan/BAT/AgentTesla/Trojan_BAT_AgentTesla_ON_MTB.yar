
rule Trojan_BAT_AgentTesla_ON_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ON!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {25 16 09 8c [0-04] a2 25 17 11 ?? 8c [0-04] a2 14 14 28 [0-04] 25 2d ?? 26 12 ?? fe [0-05] 11 ?? 2b ?? a5 [0-04] 13 ?? 11 ?? 28 [0-04] 13 ?? 08 06 11 ?? b4 9c 11 ?? 17 d6 13 ?? 11 ?? 16 31 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}