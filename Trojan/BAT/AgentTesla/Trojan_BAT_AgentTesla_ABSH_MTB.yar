
rule Trojan_BAT_AgentTesla_ABSH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABSH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {72 89 00 00 70 28 90 01 01 00 00 06 13 00 38 90 01 01 00 00 00 28 90 01 01 00 00 06 11 00 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 13 01 38 90 01 01 00 00 00 dd 90 01 03 ff 26 90 00 } //01 00 
		$a_01_1 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e } //01 00  ReadAsByteArrayAsyn
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}