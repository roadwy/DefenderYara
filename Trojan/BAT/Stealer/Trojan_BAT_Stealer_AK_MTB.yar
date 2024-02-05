
rule Trojan_BAT_Stealer_AK_MTB{
	meta:
		description = "Trojan:BAT/Stealer.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {01 57 15 a2 09 09 09 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 30 00 00 00 07 00 00 00 07 00 00 00 1a } //02 00 
		$a_01_1 = {6c 00 6f 00 61 00 64 00 65 00 72 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 } //02 00 
		$a_01_2 = {51 75 69 63 6b 65 73 74 } //02 00 
		$a_01_3 = {52 65 74 68 65 72 6d } //00 00 
	condition:
		any of ($a_*)
 
}