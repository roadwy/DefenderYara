
rule Trojan_BAT_Lazy_NL_MTB{
	meta:
		description = "Trojan:BAT/Lazy.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {72 95 01 00 70 06 73 90 01 03 0a 0b 07 6f 90 01 03 0a 0c 08 6f 90 01 03 0a 90 00 } //01 00 
		$a_01_1 = {43 4f 4c 4c 45 43 54 42 49 4f 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00 
		$a_01_2 = {43 4f 4c 4c 45 43 54 42 49 4f } //00 00 
	condition:
		any of ($a_*)
 
}