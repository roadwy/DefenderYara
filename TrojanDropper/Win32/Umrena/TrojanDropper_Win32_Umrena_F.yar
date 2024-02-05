
rule TrojanDropper_Win32_Umrena_F{
	meta:
		description = "TrojanDropper:Win32/Umrena.F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 2f 63 6c 69 63 6b 73 63 72 69 70 74 2e 74 78 74 00 } //01 00 
		$a_01_1 = {00 48 45 78 65 63 00 } //01 00 
		$a_01_2 = {01 f1 77 69 6e 74 68 75 6d 62 00 } //00 00 
	condition:
		any of ($a_*)
 
}