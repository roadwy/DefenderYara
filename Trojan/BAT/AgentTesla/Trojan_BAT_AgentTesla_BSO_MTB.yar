
rule Trojan_BAT_AgentTesla_BSO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BSO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 07 00 00 0a 00 "
		
	strings :
		$a_00_0 = {02 03 05 03 8e 69 5d 91 05 04 03 8e 69 5d d6 04 5f 61 b4 61 fe 0b 00 00 18 0c 2b ca 02 0a 06 2a } //0a 00 
		$a_02_1 = {02 03 05 03 8e 69 5d 91 05 04 03 8e 69 5d d6 04 5f 61 b4 7e 90 01 04 20 90 01 04 7e 90 01 04 20 90 01 04 93 05 60 1f 37 5f 9d 61 fe 0b 00 00 19 0c 90 00 } //0a 00 
		$a_00_2 = {02 03 05 03 8e 69 5d 91 05 04 03 8e 69 5d d6 04 5f 61 b4 61 fe 0b 00 00 16 0c 2b ca 02 0a 06 } //02 00 
		$a_80_3 = {57 65 62 52 65 71 75 65 73 74 } //WebRequest  02 00 
		$a_80_4 = {57 65 62 52 65 73 70 6f 6e 73 65 } //WebResponse  02 00 
		$a_80_5 = {47 65 74 52 65 73 70 6f 6e 73 65 } //GetResponse  02 00 
		$a_80_6 = {44 65 6c 61 79 } //Delay  00 00 
	condition:
		any of ($a_*)
 
}