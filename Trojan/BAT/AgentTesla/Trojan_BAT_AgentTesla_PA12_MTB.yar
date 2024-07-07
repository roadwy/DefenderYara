
rule Trojan_BAT_AgentTesla_PA12_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PA12!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 73 3a 2f 2f 72 61 64 69 6f 2d 68 69 74 2e 72 6f 2f } //https://radio-hit.ro/  2
		$a_01_1 = {24 62 31 61 31 66 63 30 38 2d 66 61 31 63 2d 34 37 66 38 2d 61 66 33 64 2d 31 38 32 33 31 36 36 30 39 31 61 35 } //2 $b1a1fc08-fa1c-47f8-af3d-1823166091a5
		$a_80_2 = {56 69 62 69 69 71 7a 75 6b 6b 6c 6d 67 6d } //Vibiiqzukklmgm  1
		$a_01_3 = {42 69 6e 61 72 79 52 65 61 64 65 72 } //1 BinaryReader
		$a_01_4 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_80_5 = {53 65 61 78 76 67 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //Seaxvgs.Properties.Resources.resources  1
	condition:
		((#a_80_0  & 1)*2+(#a_01_1  & 1)*2+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}