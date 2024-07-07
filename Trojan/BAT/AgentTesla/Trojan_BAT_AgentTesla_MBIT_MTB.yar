
rule Trojan_BAT_AgentTesla_MBIT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 ad 0b 00 70 72 b3 0b 00 70 6f 90 01 01 00 00 0a 72 b7 0b 00 70 72 bd 0b 00 70 90 00 } //1
		$a_01_1 = {05 7d 00 7d 00 00 03 7d 00 00 03 30 00 00 0f 20 00 4c 00 6f 00 2d 00 61 00 64 00 20 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}