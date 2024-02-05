
rule Trojan_BAT_Spynoon_ABPY_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.ABPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 04 00 "
		
	strings :
		$a_01_0 = {4f 70 74 4e 49 73 74 6f 6e 65 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_01_2 = {51 00 59 00 77 00 41 00 63 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}