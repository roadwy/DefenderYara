
rule Trojan_BAT_AgentTesla_CKI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 02 07 6f 90 01 03 0a 03 07 03 6f 90 01 03 0a 5d 6f 90 01 03 0a 61 d1 6f 90 01 03 0a 26 07 17 58 0b 07 02 6f 90 01 03 0a 3f 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_01_2 = {54 6f 43 68 61 72 41 72 72 61 79 } //00 00  ToCharArray
	condition:
		any of ($a_*)
 
}