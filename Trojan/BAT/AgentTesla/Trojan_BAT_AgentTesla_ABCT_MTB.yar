
rule Trojan_BAT_AgentTesla_ABCT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABCT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {04 08 04 8e 69 5d 7e ?? ?? ?? 04 04 08 04 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 06 04 08 17 58 04 8e 69 5d 91 59 20 ?? ?? ?? 00 58 17 58 20 ?? ?? ?? 00 5d d2 9c 08 17 58 0c 08 6a 04 8e 69 17 59 6a 06 17 58 6e 5a 31 b4 } //5
		$a_01_1 = {64 00 6d 00 6b 00 49 00 62 00 6c 00 } //1 dmkIbl
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}