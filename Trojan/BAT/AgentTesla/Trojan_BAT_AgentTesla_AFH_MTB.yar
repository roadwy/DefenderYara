
rule Trojan_BAT_AgentTesla_AFH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 0a 00 "
		
	strings :
		$a_03_0 = {09 11 04 9a 13 05 11 05 28 90 01 03 0a 23 00 00 00 00 00 80 73 40 59 28 90 01 03 0a b7 90 00 } //0a 00 
		$a_03_1 = {11 04 08 9a 13 07 11 07 28 90 01 03 0a 23 00 00 00 00 00 80 73 40 59 28 90 01 03 0a b7 90 00 } //02 00 
		$a_80_2 = {52 65 76 65 72 73 65 } //Reverse  02 00 
		$a_80_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  02 00 
		$a_80_4 = {47 65 74 54 79 70 65 73 } //GetTypes  02 00 
		$a_80_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  00 00 
	condition:
		any of ($a_*)
 
}