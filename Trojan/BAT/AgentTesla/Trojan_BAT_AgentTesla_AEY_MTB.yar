
rule Trojan_BAT_AgentTesla_AEY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AEY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 16 73 90 01 03 0a 73 90 01 03 0a 0c 08 07 6f 90 01 03 0a 90 02 05 08 6f 90 01 03 0a dc 07 6f 90 01 03 0a 0d 90 02 05 07 6f 90 01 03 0a dc 06 6f 90 01 03 0a dc 09 2a 90 00 } //01 00 
		$a_80_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  01 00 
		$a_80_2 = {47 65 74 4d 65 74 68 6f 64 73 } //GetMethods  01 00 
		$a_80_3 = {47 65 74 54 79 70 65 } //GetType  00 00 
	condition:
		any of ($a_*)
 
}