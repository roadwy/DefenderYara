
rule Trojan_Win32_Dridex_EK_MTB{
	meta:
		description = "Trojan:Win32/Dridex.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 69 67 69 6e 61 6c 2d 73 68 69 6e 65 5c 62 61 74 5c 43 61 74 5c 70 61 67 65 } //01 00 
		$a_01_1 = {44 65 73 69 67 6e 2e 64 6c 6c } //01 00 
		$a_01_2 = {46 6f 72 63 65 61 72 65 61 } //01 00 
		$a_01_3 = {53 74 61 74 69 6f 6e 6d 65 61 74 } //01 00 
		$a_01_4 = {6c 4f 77 57 54 4f 77 } //00 00 
	condition:
		any of ($a_*)
 
}