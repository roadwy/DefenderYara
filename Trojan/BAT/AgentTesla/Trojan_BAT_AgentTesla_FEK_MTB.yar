
rule Trojan_BAT_AgentTesla_FEK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {5f 0c 07 06 95 13 04 07 06 07 08 95 9e 07 08 11 04 9e 11 05 09 d4 02 09 d4 91 07 07 06 95 07 08 95 58 20 ff 00 00 00 5f 95 61 90 01 05 9c 09 17 6a 58 0d 09 11 05 8e 69 17 59 6a fe 02 16 fe 01 13 09 11 09 2d a4 90 00 } //01 00 
		$a_80_1 = {47 65 74 54 79 70 65 } //GetType  01 00 
		$a_80_2 = {47 65 74 4d 65 74 68 6f 64 } //GetMethod  00 00 
	condition:
		any of ($a_*)
 
}