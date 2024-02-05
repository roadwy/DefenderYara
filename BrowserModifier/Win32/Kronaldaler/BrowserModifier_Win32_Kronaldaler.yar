
rule BrowserModifier_Win32_Kronaldaler{
	meta:
		description = "BrowserModifier:Win32/Kronaldaler,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 63 6f 6e 4f 76 65 72 6c 61 79 45 78 2e 64 6c 6c 00 44 6c 6c } //01 00 
		$a_01_1 = {2e 00 76 00 63 00 2f 00 3f } //01 00 
		$a_01_2 = {53 00 68 00 65 00 6c 00 6c 00 20 00 4f 00 76 00 65 00 72 00 6c 00 61 00 79 00 20 00 53 00 68 00 65 00 6c 00 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}