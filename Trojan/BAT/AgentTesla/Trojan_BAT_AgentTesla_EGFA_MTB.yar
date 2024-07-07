
rule Trojan_BAT_AgentTesla_EGFA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EGFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {5a 1f 16 58 0c 2b 18 00 7e 26 00 00 04 07 08 20 00 01 00 00 28 90 01 03 06 0b 00 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d dd 90 00 } //1
		$a_01_1 = {49 4f 44 53 49 46 44 53 } //1 IODSIFDS
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}