
rule Trojan_BAT_AgentTesla_AHE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {04 09 11 05 6f 90 01 03 0a 13 06 04 09 11 05 6f 90 01 03 0a 13 07 11 07 28 90 01 03 0a 13 08 07 06 11 08 28 90 01 03 0a 9c 11 05 17 d6 13 05 11 05 11 04 31 cb 90 00 } //0a 00 
		$a_03_1 = {0a 16 9a 14 72 90 01 03 70 17 8d 90 01 03 01 25 16 03 a2 25 13 04 14 14 17 8d 90 01 03 01 25 16 17 9c 25 13 05 28 90 01 03 0a 11 05 16 91 2d 02 2b 0b 11 04 16 9a 90 00 } //02 00 
		$a_80_2 = {47 65 74 54 79 70 65 } //GetType  02 00 
		$a_80_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  02 00 
		$a_80_4 = {52 65 76 65 72 73 65 } //Reverse  00 00 
	condition:
		any of ($a_*)
 
}