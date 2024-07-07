
rule Trojan_BAT_AgentTesla_AUB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AUB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_02_0 = {0a 0b 09 16 73 90 01 03 0a 73 90 01 03 0a 13 04 11 04 07 6f 90 01 03 0a 90 01 05 11 04 6f 90 01 03 0a dc 07 6f 90 01 03 0a 13 05 90 01 05 07 6f 90 01 03 0a dc 90 01 05 09 6f 90 01 03 0a dc 90 00 } //10
		$a_80_1 = {43 6c 61 73 73 4c 69 62 72 61 72 79 31 2e 64 6c 6c } //ClassLibrary1.dll  1
		$a_80_2 = {4e 65 77 74 6f 6e 73 6f 66 74 2e 4a 73 6f 6e 2e 64 6c 6c } //Newtonsoft.Json.dll  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=11
 
}