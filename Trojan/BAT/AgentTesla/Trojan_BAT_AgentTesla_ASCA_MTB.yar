
rule Trojan_BAT_AgentTesla_ASCA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 25 26 20 [0-04] 28 ?? 00 00 06 25 26 6f ?? 00 00 0a 0a 08 20 [0-04] 5a 20 [0-04] 61 38 ?? ff ff ff 06 28 ?? 00 00 0a 0b 08 20 [0-04] 5a 20 [0-04] 61 38 } //4
		$a_01_1 = {42 4e 6e 48 68 38 37 24 } //1 BNnHh87$
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}