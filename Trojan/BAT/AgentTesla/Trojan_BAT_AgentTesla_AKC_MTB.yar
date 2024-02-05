
rule Trojan_BAT_AgentTesla_AKC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {25 16 03 a2 25 0d 14 14 17 8d 90 01 03 01 25 16 17 9c 25 13 04 28 90 01 03 0a 11 04 16 91 2d 02 2b 0a 09 16 9a 28 90 01 03 0a 10 01 74 90 01 03 01 0b 07 72 90 01 03 70 6f 90 01 03 0a 0c 08 19 90 00 } //02 00 
		$a_80_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  02 00 
		$a_80_2 = {47 65 74 54 79 70 65 } //GetType  00 00 
	condition:
		any of ($a_*)
 
}