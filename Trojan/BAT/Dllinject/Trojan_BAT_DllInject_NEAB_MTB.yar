
rule Trojan_BAT_DllInject_NEAB_MTB{
	meta:
		description = "Trojan:BAT/DllInject.NEAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {38 63 65 36 36 35 65 34 2d 63 35 31 33 2d 34 61 66 62 2d 61 36 35 31 2d 32 61 30 32 63 35 30 34 61 39 38 33 } //05 00 
		$a_01_1 = {50 72 65 63 69 73 69 6f 6e 2e 64 6c 6c } //02 00 
		$a_01_2 = {42 61 6e 6e 69 6f 6e 65 73 74 } //02 00 
		$a_01_3 = {54 77 65 65 74 65 72 } //01 00 
		$a_01_4 = {4d 61 6e 61 67 65 6d 65 6e 74 20 63 6f 6e 73 75 6c 74 61 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}