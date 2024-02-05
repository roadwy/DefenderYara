
rule Trojan_BAT_Quasar_MA_MTB{
	meta:
		description = "Trojan:BAT/Quasar.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 69 6e 65 6d 61 4f 74 6f 6d 61 73 79 6f 6e 56 69 7a 65 2e 65 78 65 } //0a 00 
		$a_01_1 = {51 00 7a 00 70 00 63 00 58 00 46 00 64 00 70 00 62 00 6d 00 52 00 76 00 64 00 33 00 4e 00 63 00 58 00 45 00 31 00 70 00 59 00 33 00 4a 00 76 00 63 00 32 00 } //02 00 
		$a_01_2 = {43 61 73 70 6f 6c } //02 00 
		$a_01_3 = {44 6f 6e 75 73 } //01 00 
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //00 00 
	condition:
		any of ($a_*)
 
}