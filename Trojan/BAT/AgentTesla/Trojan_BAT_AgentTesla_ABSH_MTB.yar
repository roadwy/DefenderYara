
rule Trojan_BAT_AgentTesla_ABSH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABSH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {72 89 00 00 70 28 ?? 00 00 06 13 00 38 ?? 00 00 00 28 ?? 00 00 06 11 00 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 06 13 01 38 ?? 00 00 00 dd ?? ?? ?? ff 26 } //5
		$a_01_1 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e } //1 ReadAsByteArrayAsyn
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}