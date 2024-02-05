
rule Trojan_BAT_RedLine_RDCF_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 6f 75 63 68 6f 72 72 75 6d 6d 61 67 79 } //01 00 
		$a_01_1 = {64 6f 72 61 79 43 61 74 68 61 } //01 00 
		$a_01_2 = {64 6f 72 61 79 45 76 65 6e 73 } //01 00 
		$a_01_3 = {63 61 74 68 61 42 61 6e 64 61 72 } //00 00 
	condition:
		any of ($a_*)
 
}