
rule Trojan_BAT_AgentTesla_NEAC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {11 19 11 1a 9a 13 09 11 09 72 53 02 00 70 72 61 02 00 70 72 69 02 00 70 6f ba 00 00 0a 17 28 bb 00 00 0a 2d 07 17 0b 38 ae 00 00 00 11 09 72 6f 02 00 70 72 83 02 00 70 72 8d 02 00 70 6f ba 00 00 0a 19 6f bc 00 00 0a 2c 62 11 09 17 8d 35 00 00 01 13 1b 11 1b 16 72 95 02 00 70 a2 11 1b 18 17 6f bd 00 00 0a 13 0a 11 0a 8e 69 18 2e 21 } //02 00 
		$a_01_1 = {2d 00 65 00 78 00 74 00 64 00 75 00 6d 00 6d 00 74 00 } //02 00  -extdummt
		$a_01_2 = {2d 00 77 00 68 00 61 00 74 00 74 00 } //02 00  -whatt
		$a_01_3 = {2d 00 64 00 65 00 62 00 75 00 67 00 } //02 00  -debug
		$a_01_4 = {67 00 67 00 2e 00 65 00 78 00 65 00 } //00 00  gg.exe
	condition:
		any of ($a_*)
 
}