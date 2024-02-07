
rule Trojan_BAT_AgentTesla_EAQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {1d 2d 1c 26 28 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 1b 2d 06 26 de 09 0a 2b e2 0b 2b f8 26 de d2 90 00 } //02 00 
		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 36 00 31 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00  WindowsFormsApp61.Properties.Resources
	condition:
		any of ($a_*)
 
}