
rule Trojan_BAT_AgentTesla_NEAM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0b 03 8e 69 0c 03 04 08 5d 91 07 04 1f 16 5d 91 61 28 90 01 01 00 00 0a 03 04 17 58 08 5d 91 28 90 01 01 00 00 0a 59 06 58 06 5d d2 0d 2b 00 09 2a 90 00 } //01 00 
		$a_01_1 = {49 6e 76 6f 6b 65 } //01 00  Invoke
		$a_01_2 = {41 73 73 65 6d 62 6c 79 54 69 74 6c 65 41 74 74 72 69 62 75 74 65 } //00 00  AssemblyTitleAttribute
	condition:
		any of ($a_*)
 
}