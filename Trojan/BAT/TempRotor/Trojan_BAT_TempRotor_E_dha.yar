
rule Trojan_BAT_TempRotor_E_dha{
	meta:
		description = "Trojan:BAT/TempRotor.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 64 00 "
		
	strings :
		$a_01_0 = {53 65 74 43 6f 6e 66 69 67 00 53 65 6e 64 00 47 65 74 43 6f 6e 66 69 67 } //00 00 
	condition:
		any of ($a_*)
 
}