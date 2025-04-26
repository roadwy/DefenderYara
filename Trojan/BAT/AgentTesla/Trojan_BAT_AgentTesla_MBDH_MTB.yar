
rule Trojan_BAT_AgentTesla_MBDH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {24 33 65 61 39 35 63 62 37 2d 30 64 66 34 2d 34 65 62 36 2d 61 66 31 64 2d 38 34 63 33 65 64 33 39 38 31 34 65 } //1 $3ea95cb7-0df4-4eb6-af1d-84c3ed39814e
		$a_01_1 = {50 75 7a 7a 6c 65 47 61 6d 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 PuzzleGame.Properties.Resources.resource
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_MBDH_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 19 00 07 06 08 8f ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 00 08 17 59 0c 08 15 fe 02 0d 09 2d df } //1
		$a_01_1 = {36 61 65 62 38 62 63 32 2d 33 65 32 36 2d 34 62 63 38 2d 62 36 30 39 2d 63 30 33 38 64 36 34 66 66 61 39 66 } //1 6aeb8bc2-3e26-4bc8-b609-c038d64ffa9f
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}