
rule Trojan_BAT_Remcos_ABJV_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ABJV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 69 6d 75 6c 61 74 69 6f 6e 52 65 6d 6f 6e 74 65 65 53 6b 69 2e 54 31 2e 72 65 73 6f 75 72 63 65 73 00 } //01 00 
		$a_01_1 = {53 00 69 00 6d 00 75 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 52 00 65 00 6d 00 6f 00 6e 00 74 00 65 00 65 00 53 00 6b 00 69 00 } //00 00 
	condition:
		any of ($a_*)
 
}