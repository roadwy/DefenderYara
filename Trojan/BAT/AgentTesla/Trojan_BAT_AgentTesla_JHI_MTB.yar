
rule Trojan_BAT_AgentTesla_JHI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JHI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_03_0 = {0a 25 26 fe 90 01 02 00 fe 90 01 02 00 fe 90 01 02 00 6f 90 01 03 0a 25 26 5d 6f 90 01 03 0a 25 26 61 d1 6f 90 01 03 0a 25 26 26 fe 90 01 02 00 20 90 01 03 00 58 fe 90 01 02 00 fe 90 01 02 00 fe 90 01 02 00 6f 90 00 } //10
		$a_81_1 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_81_2 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_81_4 = {47 65 74 53 74 72 69 6e 67 } //1 GetString
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=14
 
}