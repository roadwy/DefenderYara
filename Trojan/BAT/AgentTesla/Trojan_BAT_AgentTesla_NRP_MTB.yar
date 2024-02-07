
rule Trojan_BAT_AgentTesla_NRP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NRP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 fd a3 3d 09 0e 00 00 00 00 00 00 00 00 00 00 01 00 00 00 40 00 00 00 25 00 00 00 } //01 00 
		$a_01_1 = {c2 86 c2 86 c2 86 c2 86 c2 86 c2 86 c2 86 c2 86 c2 87 c2 8e } //01 00 
		$a_01_2 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //01 00  FromBase64CharArray
		$a_01_4 = {63 62 52 65 73 65 72 76 65 64 32 } //01 00  cbReserved2
		$a_01_5 = {53 79 73 74 65 6d 2e 54 65 78 74 } //01 00  System.Text
		$a_01_6 = {6c 70 44 65 73 6b 74 6f 70 } //01 00  lpDesktop
		$a_01_7 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_8 = {62 61 73 65 36 34 45 6e 63 6f 64 65 64 44 61 74 61 } //00 00  base64EncodedData
	condition:
		any of ($a_*)
 
}