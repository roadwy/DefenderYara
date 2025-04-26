
rule Trojan_BAT_AgentTesla_EPE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 2e 35 a3 a8 83 e6 d5 88 b9 6b 20 a2 17 31 41 59 8a 95 1e bc d2 b2 ca e1 f7 13 b7 09 ef 3d 92 2d df f5 70 f8 65 b6 45 71 27 57 ca 97 c9 d3 0d } //1
		$a_01_1 = {db d0 5d b4 30 79 b6 48 6d 21 5c 3b a8 26 11 a6 4d 77 72 65 46 b3 cb 2e 43 81 d5 5e 86 4a 1a 1a 65 ca 84 28 6e 5f 4b 24 55 63 4d 46 21 25 a3 fb } //1
		$a_01_2 = {b5 bb 2a 25 4f b4 27 5e b7 b7 5d 27 57 ca 97 c9 23 a6 a5 22 5c 5e b5 bb 2a 25 4f b4 27 5e b7 b7 5d 27 57 ca 97 c9 23 a6 a5 22 5c 5e b5 bb 2a 25 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}