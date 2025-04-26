
rule Trojan_BAT_AgentTesla_MBKN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBKN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 5d d4 91 08 11 07 08 8e 69 6a 5d d4 91 61 28 ?? 00 00 0a 07 11 07 17 6a 58 07 8e 69 6a 5d d4 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d } //1
		$a_01_1 = {39 00 43 00 38 00 38 00 35 00 47 00 35 00 37 00 34 00 35 00 59 00 35 00 4a 00 41 00 42 00 38 00 34 00 38 00 38 00 46 00 45 00 55 00 } //1 9C885G5745Y5JAB8488FEU
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}