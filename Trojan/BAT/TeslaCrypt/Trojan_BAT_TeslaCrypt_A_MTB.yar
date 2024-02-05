
rule Trojan_BAT_TeslaCrypt_A_MTB{
	meta:
		description = "Trojan:BAT/TeslaCrypt.A!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 65 74 72 69 73 2e 4d 79 } //01 00 
		$a_01_1 = {54 6f 43 68 61 72 41 72 72 61 79 } //01 00 
		$a_01_2 = {52 65 76 65 72 73 65 } //00 00 
	condition:
		any of ($a_*)
 
}