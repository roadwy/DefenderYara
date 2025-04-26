
rule Trojan_BAT_AgentTesla_NUQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NUQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {04 03 1f 16 5d 28 ?? ?? ?? ?? 61 0b 08 20 } //1
		$a_03_1 = {06 03 04 17 58 20 00 78 00 00 5d 91 28 ?? 00 00 06 59 05 58 05 5d 0a } //1
		$a_01_2 = {61 30 33 34 31 37 30 33 64 63 66 65 } //1 a0341703dcfe
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}