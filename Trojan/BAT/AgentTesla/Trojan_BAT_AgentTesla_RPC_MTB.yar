
rule Trojan_BAT_AgentTesla_RPC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_03_0 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 90 02 70 2e 00 70 00 6e 00 67 00 90 00 } //01 00 
		$a_01_1 = {49 6e 76 6f 6b 65 } //01 00  Invoke
		$a_01_2 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_3 = {57 65 62 52 65 73 70 6f 6e 73 65 } //01 00  WebResponse
		$a_01_4 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_5 = {57 72 69 74 65 } //01 00  Write
		$a_01_6 = {54 6f 53 74 72 69 6e 67 } //01 00  ToString
		$a_01_7 = {52 65 61 64 42 79 74 65 73 } //01 00  ReadBytes
		$a_01_8 = {57 65 62 52 65 71 75 65 73 74 } //01 00  WebRequest
		$a_01_9 = {54 6f 41 72 72 61 79 } //00 00  ToArray
	condition:
		any of ($a_*)
 
}