
rule Trojan_BAT_AgentTesla_ABPX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 02 8e 69 17 da 0c 16 0d 2b 37 09 1c 5d 16 fe 01 13 04 11 04 2c 16 07 02 09 9a 28 90 01 03 0a 1c 6a 61 b4 6f 90 01 03 0a 00 00 2b 11 00 07 02 09 9a 28 90 01 03 0a 6f 90 01 03 0a 00 00 09 17 d6 0d 09 08 31 c5 07 6f 90 01 03 0a 0a 2b 00 06 2a 90 00 } //4
		$a_01_1 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_2 = {4d 00 65 00 74 00 72 00 6f 00 70 00 6f 00 6c 00 69 00 73 00 5f 00 4c 00 61 00 75 00 6e 00 63 00 68 00 65 00 72 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Metropolis_Launcher.Resources
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}