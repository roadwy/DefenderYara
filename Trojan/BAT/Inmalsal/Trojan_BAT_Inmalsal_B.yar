
rule Trojan_BAT_Inmalsal_B{
	meta:
		description = "Trojan:BAT/Inmalsal.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 65 62 43 6c 69 65 6e 74 00 53 79 73 74 65 6d 2e 4e 65 74 } //01 00 
		$a_01_1 = {73 76 63 68 6f 73 74 2e 65 78 65 00 6d 73 63 6f 72 6c 69 62 } //01 00 
		$a_03_2 = {73 76 63 68 6f 73 74 2e 90 01 01 2e 72 65 73 6f 75 72 63 65 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}