
rule Trojan_BAT_AgentTesla_CEI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CEI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {c1 00 c3 00 de 00 be 00 ae 00 ae 00 ba 00 ae 00 ae 00 ae 00 ae 00 b2 00 ae 00 ae 00 ae 00 ae 00 } //01 00 
		$a_00_1 = {e2 00 d4 00 a1 00 ae 00 e1 00 ae 00 db 00 bb 00 b6 00 cf 00 d4 00 af 00 c1 00 ba 00 9d 00 d5 00 c3 00 b4 00 d5 00 dd 00 d0 00 e6 00 af 00 e4 00 d0 00 da 00 a6 00 db } //01 00 
		$a_81_2 = {54 68 72 65 61 64 50 6f 6f 6c 2e 4c 69 67 68 74 } //01 00 
		$a_81_3 = {47 65 74 54 79 70 65 } //01 00 
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_81_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00 
		$a_81_6 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}