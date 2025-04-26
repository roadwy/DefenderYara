
rule Trojan_BAT_AgentTesla_EDF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {e7 02 e1 02 08 03 0b 03 09 03 f6 02 f5 02 f8 02 e3 02 04 03 01 03 e5 02 e3 02 ea 02 e6 02 15 03 11 03 f2 02 e1 02 f2 02 06 03 06 03 cd 02 cd 02 cd 02 cd 02 df 02 0d 03 d3 02 0e 03 e4 02 cf 02 07 03 } //1
		$a_01_1 = {47 00 65 00 74 00 4d 00 65 00 74 00 68 00 6f 00 64 00 } //1 GetMethod
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}