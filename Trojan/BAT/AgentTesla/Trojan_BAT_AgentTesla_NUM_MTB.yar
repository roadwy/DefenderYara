
rule Trojan_BAT_AgentTesla_NUM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NUM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0b 00 07 28 90 01 03 0a 72 70 01 00 70 6f 90 01 03 0a 6f 90 01 03 0a 0c 06 08 6f 90 01 03 0a 00 06 18 6f 90 01 03 0a 00 03 0d 06 6f 90 01 01 00 00 0a 09 16 09 8e 69 6f 90 01 01 00 00 0a 13 04 de 16 90 00 } //01 00 
		$a_01_1 = {52 00 75 00 65 00 75 00 61 00 75 00 72 00 73 00 6c 00 65 00 6e 00 66 00 7a 00 71 00 75 00 2e 00 42 00 70 00 6f 00 72 00 68 00 73 00 6a 00 62 00 6f 00 67 00 6e 00 67 00 72 00 71 00 } //00 00 
	condition:
		any of ($a_*)
 
}