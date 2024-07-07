
rule Trojan_BAT_AgentTesla_DPB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 02 08 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 84 28 90 01 03 0a 6f 90 01 03 0a 26 08 18 d6 0c 90 00 } //1
		$a_03_1 = {08 07 02 07 91 11 04 61 09 06 91 61 28 90 01 03 0a 9c 06 03 6f 90 01 03 0a 17 59 33 04 16 0a 2b 04 06 17 58 0a 07 17 58 0b 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}