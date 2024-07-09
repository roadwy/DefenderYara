
rule Trojan_BAT_AgentTesla_NTT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 ee db d0 24 25 26 fe ?? ?? 00 20 ?? ?? ?? 38 5b 61 38 ?? ?? ?? ff 00 fe ?? ?? 00 fe ?? ?? 00 20 ?? ?? ?? 00 8d ?? ?? ?? 01 fe ?? ?? 00 fe ?? ?? 00 20 ?? ?? ?? 00 } //5
		$a_01_1 = {52 61 79 58 2e 50 72 6f 70 65 72 74 69 65 73 } //1 RayX.Properties
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_NTT_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 0a 03 02 20 00 14 01 00 04 28 ?? 00 00 06 03 04 17 58 20 00 14 01 00 5d 91 59 06 58 06 5d 0b 03 04 20 00 14 01 00 5d 07 d2 9c 03 0c 2b 00 } //1
		$a_03_1 = {02 05 04 5d 91 03 05 1f 16 5d 6f ?? ?? ?? 0a 61 0a 2b 00 06 2a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}