
rule Trojan_BAT_AgentTesla_GKS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GKS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {56 6a 46 6b 64 31 51 78 52 58 64 4e 56 57 68 54 59 6b 64 6f 55 56 59 77 57 6d 46 6a 56 6c 4a 59 5a 55 56 30 54 6d 4a 49 51 6b 64 5a 56 56 70 50 56 44 46 4a 65 46 4e 72 54 6c 5a 53 62 45 59 7a 56 55 5a 46 4f 56 42 52 50 54 30 3d } //VjFkd1QxRXdNVWhTYkdoUVYwWmFjVlJYZUV0TmJIQkdZVVpPVDFJeFNrTlZSbEYzVUZFOVBRPT0=  1
		$a_80_1 = {56 6a 46 61 55 31 4d 78 57 58 64 4f 56 6d 52 71 55 6c 64 6f 55 56 5a 72 56 6b 74 6a 62 46 56 33 57 6b 63 31 61 32 52 36 4d 44 6b 3d } //VjFaU1MxWXdOVmRqUldoUVZrVktjbFV3Wkc1a2R6MDk=  1
		$a_01_2 = {54 6f 53 74 72 69 6e 67 } //1 ToString
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}