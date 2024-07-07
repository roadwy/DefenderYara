
rule Trojan_BAT_AgentTesla_ABOX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABOX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 09 08 1f 10 6f 90 01 03 0a 6f 90 01 03 0a 09 08 1f 10 6f 90 01 03 0a 6f 90 01 03 0a 09 6f 90 01 03 0a 07 16 07 8e 69 6f 90 01 03 0a 13 04 11 04 8e 69 1f 10 59 8d 90 01 03 01 13 05 11 04 90 00 } //5
		$a_01_1 = {53 00 69 00 6d 00 75 00 6c 00 61 00 63 00 69 00 6f 00 6e 00 41 00 62 00 65 00 6a 00 61 00 73 00 48 00 69 00 6c 00 6f 00 73 00 } //1 SimulacionAbejasHilos
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}