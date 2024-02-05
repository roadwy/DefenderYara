
rule Trojan_BAT_AsyncRAT_V_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {30 30 37 53 74 75 62 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //02 00 
		$a_01_1 = {30 30 37 53 74 75 62 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_01_3 = {43 72 65 61 74 65 54 68 72 65 61 64 } //00 00 
	condition:
		any of ($a_*)
 
}