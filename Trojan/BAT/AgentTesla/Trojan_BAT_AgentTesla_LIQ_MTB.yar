
rule Trojan_BAT_AgentTesla_LIQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LIQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {fe 0c 02 00 20 00 00 00 00 73 aa 00 00 0a fe 0e 03 00 fe 0c 03 00 73 ab 00 00 0a fe 0e 04 00 fe 0c 04 00 6f ac 00 00 0a fe 0e 01 00 dd 39 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00 
		$a_01_2 = {44 65 63 6f 6d 70 72 65 73 73 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}