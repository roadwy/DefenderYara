
rule Trojan_BAT_AgentTesla_MAC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 94 02 28 09 02 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 1b 00 00 00 04 00 00 00 3f 00 00 00 1c 00 00 00 21 00 00 00 04 00 00 00 01 00 00 00 1b 00 00 00 06 00 00 00 01 00 00 00 01 00 00 00 01 00 } //5
		$a_01_1 = {0b 01 0b 00 00 fc 02 00 00 08 00 00 00 00 00 00 9e 1b 03 00 00 20 00 00 00 20 03 } //5
		$a_01_2 = {2e 73 64 61 74 61 } //2 .sdata
		$a_01_3 = {5f 43 6f 6d 43 54 4c } //2 _ComCTL
		$a_03_4 = {4d 69 63 67 5f 4d [0-06] 6f 78 79 } //2
		$a_01_5 = {5f 33 44 5f 46 6c 79 69 6e 67 72 65 65 73 } //2 _3D_Flyingrees
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_03_4  & 1)*2+(#a_01_5  & 1)*2) >=18
 
}