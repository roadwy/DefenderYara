
rule Trojan_BAT_PureLogStealer_RDN_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.RDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 31 66 32 61 33 62 34 2d 63 35 64 36 2d 37 38 39 30 2d 61 62 63 64 2d 31 32 33 34 35 65 66 36 37 38 39 30 } //2 e1f2a3b4-c5d6-7890-abcd-12345ef67890
		$a_01_1 = {56 65 72 74 65 78 44 79 6e 61 6d 69 63 73 } //1 VertexDynamics
		$a_01_2 = {45 6e 67 69 6e 65 65 72 69 6e 67 20 6e 65 78 74 2d 67 65 6e 20 73 6f 6c 75 74 69 6f 6e 73 20 66 6f 72 20 74 6f 64 61 79 27 73 20 63 68 61 6c 6c 65 6e 67 65 73 } //1 Engineering next-gen solutions for today's challenges
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}