
rule Trojan_BAT_AgentTesla_BSO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BSO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 07 00 00 "
		
	strings :
		$a_00_0 = {02 03 05 03 8e 69 5d 91 05 04 03 8e 69 5d d6 04 5f 61 b4 61 fe 0b 00 00 18 0c 2b ca 02 0a 06 2a } //10
		$a_02_1 = {02 03 05 03 8e 69 5d 91 05 04 03 8e 69 5d d6 04 5f 61 b4 7e ?? ?? ?? ?? 20 ?? ?? ?? ?? 7e ?? ?? ?? ?? 20 ?? ?? ?? ?? 93 05 60 1f 37 5f 9d 61 fe 0b 00 00 19 0c } //10
		$a_00_2 = {02 03 05 03 8e 69 5d 91 05 04 03 8e 69 5d d6 04 5f 61 b4 61 fe 0b 00 00 16 0c 2b ca 02 0a 06 } //10
		$a_80_3 = {57 65 62 52 65 71 75 65 73 74 } //WebRequest  2
		$a_80_4 = {57 65 62 52 65 73 70 6f 6e 73 65 } //WebResponse  2
		$a_80_5 = {47 65 74 52 65 73 70 6f 6e 73 65 } //GetResponse  2
		$a_80_6 = {44 65 6c 61 79 } //Delay  2
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*10+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2+(#a_80_6  & 1)*2) >=18
 
}