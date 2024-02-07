
rule Trojan_BAT_AgentTesla_DAX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {2b 14 2b 19 2b 1e 15 2d 06 26 16 2d 04 de 22 2b 1a 19 2c ec 2b f4 28 90 01 01 00 00 06 2b e5 28 90 01 01 00 00 2b 2b e0 28 90 01 01 00 00 2b 2b db 0a 2b e3 26 de cb 90 00 } //01 00 
		$a_01_1 = {52 65 76 65 72 73 65 } //00 00  Reverse
	condition:
		any of ($a_*)
 
}