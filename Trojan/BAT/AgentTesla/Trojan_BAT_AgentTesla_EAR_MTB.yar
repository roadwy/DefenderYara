
rule Trojan_BAT_AgentTesla_EAR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 22 15 2d 14 26 16 2d f7 2b 20 2b 25 2b 26 2b 2b 2b 30 17 2d 07 26 de 3d 2b 2f 2b e9 2b 2e 16 2d f9 2b f3 28 ?? 00 00 06 2b d7 28 ?? 00 00 0a 2b d9 06 2b d8 6f ?? 00 00 0a 2b d3 28 ?? 00 00 0a 2b ce 28 ?? 00 00 06 2b c9 0a 2b ce 0b 2b cf 26 dd } //3
		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 36 00 38 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //2 WindowsFormsApp68.Properties.Resources
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}