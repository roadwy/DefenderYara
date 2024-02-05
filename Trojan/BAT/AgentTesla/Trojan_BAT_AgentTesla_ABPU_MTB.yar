
rule Trojan_BAT_AgentTesla_ABPU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABPU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {4f 53 74 6f 63 6b 5f 53 69 6d 75 6c 61 74 69 6f 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00 
		$a_01_1 = {47 65 74 4f 62 6a 65 63 74 } //01 00 
		$a_01_2 = {52 65 70 6c 61 63 65 } //01 00 
		$a_01_3 = {4f 00 53 00 74 00 6f 00 63 00 6b 00 20 00 53 00 69 00 6d 00 75 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 } //00 00 
	condition:
		any of ($a_*)
 
}