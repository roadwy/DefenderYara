
rule Trojan_BAT_AgentTesla_ASWAT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASWAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {06 02 7b 02 00 00 04 6f 4a 00 00 0a 6f 4b 00 00 0a 0b 02 07 72 dd 06 00 70 28 16 00 00 06 02 7b 01 00 00 04 6f 34 00 00 0a 2d 56 28 4c 00 00 0a } //01 00 
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //00 00  DownloadString
	condition:
		any of ($a_*)
 
}