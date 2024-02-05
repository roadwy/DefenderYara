
rule BrowserModifier_Win32_Shebooren{
	meta:
		description = "BrowserModifier:Win32/Shebooren,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 65 42 72 6f 77 73 65 72 43 6d 70 2e 44 4c 4c 00 } //01 00 
		$a_01_1 = {46 66 42 72 6f 77 73 65 72 43 6d 70 2e 64 6c 6c 00 } //05 00 
		$a_01_2 = {55 00 72 00 6c 00 52 00 65 00 64 00 69 00 72 00 65 00 63 00 74 00 6f 00 72 00 2e 00 63 00 70 00 70 00 00 00 } //05 00 
		$a_03_3 = {32 c3 24 0f 32 c3 6a 01 8d 4c 24 90 01 01 04 90 01 01 51 8d 4c 24 90 01 01 88 44 24 90 01 01 e8 90 01 04 8a 06 84 c0 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}