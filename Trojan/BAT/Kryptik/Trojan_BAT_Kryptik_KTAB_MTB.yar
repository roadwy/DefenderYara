
rule Trojan_BAT_Kryptik_KTAB_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.KTAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {4c 65 70 65 6c 4c 65 65 67 } //02 00 
		$a_01_1 = {52 65 6d 6f 76 65 44 61 74 53 68 69 74 } //03 00 
		$a_01_2 = {56 65 72 6b 6c 65 70 65 72 69 6a } //02 00 
		$a_01_3 = {00 50 61 79 00 } //00 00 
	condition:
		any of ($a_*)
 
}