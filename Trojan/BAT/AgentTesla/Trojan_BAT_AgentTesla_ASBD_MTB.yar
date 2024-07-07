
rule Trojan_BAT_AgentTesla_ASBD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 09 8e 69 17 da 13 0b 16 13 0c 2b 1b 11 04 11 0c 09 11 0c 9a 1f 10 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 11 0c 17 d6 13 0c 11 0c 11 0b 31 df 90 00 } //4
		$a_01_1 = {4d 00 4e 00 29 00 32 00 31 00 29 00 4c 00 38 00 29 00 26 00 31 00 29 00 34 00 4d 00 29 00 4d 00 4e 00 29 00 32 00 31 00 29 00 35 00 34 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}