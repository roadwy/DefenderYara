
rule Trojan_BAT_AgentTesla_GN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0a 06 14 19 8d ?? ?? ?? 01 25 16 7e ?? ?? ?? 04 a2 25 17 7e ?? ?? ?? ?? a2 25 18 72 ?? ?? ?? 70 a2 14 6f ?? ?? ?? 0a [0-10] 2a } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_GN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 11 07 7e 01 00 00 04 11 07 91 7e 01 00 00 04 16 91 61 d2 9c 11 07 17 58 13 07 20 15 00 cf 30 20 00 00 80 00 58 20 00 00 80 00 59 fe 0e 0b 00 fe 0d 0b 00 00 48 68 d3 13 0a 38 } //1
		$a_01_1 = {63 6f 73 74 75 72 61 2e 63 6f 73 74 75 72 61 2e 64 6c 6c 2e 63 6f 6d 70 72 65 73 73 65 64 } //1 costura.costura.dll.compressed
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_GN_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {06 08 06 8e 69 6a 5d d4 06 08 06 8e 69 6a 5d d4 91 07 08 07 8e 69 6a 5d d4 91 61 28 ?? ?? ?? 0a 06 08 17 6a 58 06 8e 69 6a 5d d4 91 28 ?? ?? ?? 0a 59 20 ?? ?? ?? 00 58 20 ?? ?? ?? 00 5d 28 ?? ?? ?? 0a 9c 00 08 17 6a 58 0c 08 06 8e 69 17 59 6a 02 17 58 6e 5a fe 02 16 fe 01 0d 09 2d a0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}