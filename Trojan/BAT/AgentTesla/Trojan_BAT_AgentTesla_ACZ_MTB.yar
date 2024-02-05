
rule Trojan_BAT_AgentTesla_ACZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ACZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 19 8d 90 01 03 01 25 16 7e 90 01 03 04 a2 25 17 7e 90 01 03 04 a2 25 18 72 90 01 03 70 a2 28 90 01 03 0a 26 20 00 08 00 00 0a 2b 00 06 2a 90 00 } //02 00 
		$a_80_1 = {54 6f 43 68 61 72 41 72 72 61 79 } //ToCharArray  02 00 
		$a_80_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  02 00 
		$a_80_3 = {46 72 6f 6d 42 61 73 65 36 34 } //FromBase64  02 00 
		$a_80_4 = {46 6f 72 4e 65 78 74 43 68 65 63 6b 4f 62 6a } //ForNextCheckObj  00 00 
	condition:
		any of ($a_*)
 
}