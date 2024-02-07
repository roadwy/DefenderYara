
rule Trojan_BAT_AgentTesla_ABNH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABNH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {01 0b 07 6f 90 01 03 0a 0c 73 90 01 03 0a 0d 08 6f 90 01 03 0a 09 6f 90 01 03 0a 00 09 6f 90 01 03 0a 0a 2b 00 06 2a 90 00 } //01 00 
		$a_01_1 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_2 = {52 00 65 00 63 00 6f 00 6e 00 74 00 65 00 63 00 68 00 2e 00 4e 00 65 00 74 00 } //00 00  Recontech.Net
	condition:
		any of ($a_*)
 
}