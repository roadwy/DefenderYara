
rule Trojan_BAT_AgentTesla_NCW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 07 08 09 93 66 d1 ?? ?? ?? ?? ?? 26 00 09 17 58 0d 09 08 8e 69 fe 04 13 04 11 04 2d e2 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AgentTesla_NCW_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 06 07 25 17 58 0b 02 08 91 20 aa 00 00 00 61 d2 9c 06 07 25 17 58 0b 02 08 91 1a 63 02 08 91 1a 62 60 d2 9c 00 08 17 58 0c 08 02 8e 69 fe 04 13 04 11 04 2d ca } //2
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}