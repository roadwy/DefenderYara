
rule Trojan_BAT_AgentTesla_SOD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SOD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_03_0 = {13 05 09 11 05 09 90 01 05 1e 5b 90 01 0a 09 11 05 09 90 01 05 1e 5b 90 01 0a 09 17 90 01 05 08 09 90 01 05 17 90 01 05 13 06 11 06 02 16 02 8e 69 90 00 } //10
		$a_80_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  2
		$a_80_2 = {47 65 74 54 79 70 65 } //GetType  2
		$a_80_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //InvokeMember  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=16
 
}