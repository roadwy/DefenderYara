
rule Trojan_BAT_AgentTesla_CT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {06 20 00 01 00 00 6f 90 01 03 0a 06 20 90 01 03 00 6f 90 01 03 0a 7e 04 00 00 04 7e 03 00 00 04 20 90 01 03 00 73 90 02 06 2d 43 26 06 07 06 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 06 07 06 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 06 17 6f 90 01 03 0a 02 06 6f 90 00 } //10
		$a_81_1 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //1 ClassLibrary
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1) >=11
 
}