
rule Trojan_BAT_AgentTesla_FAT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {13 1e 16 13 1f 2b 28 00 11 1d 11 1f 18 6f 90 01 01 00 00 0a 20 03 02 00 00 28 90 01 01 00 00 0a 13 21 11 1e 11 21 6f 90 01 01 00 00 0a 00 11 1f 18 58 13 1f 00 11 1f 11 1d 6f 90 01 01 00 00 0a fe 04 13 22 11 22 2d c7 90 00 } //02 00 
		$a_01_1 = {53 00 75 00 64 00 6f 00 6b 00 75 00 43 00 57 00 4c 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}