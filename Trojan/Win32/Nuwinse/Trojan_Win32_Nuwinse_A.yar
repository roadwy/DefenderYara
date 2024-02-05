
rule Trojan_Win32_Nuwinse_A{
	meta:
		description = "Trojan:Win32/Nuwinse.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {61 6e 79 77 c7 90 01 04 ff 68 65 72 65 c7 90 01 04 ff 2e 4e 45 54 88 90 01 04 ff e8 90 00 } //01 00 
		$a_03_1 = {89 bd 8c c7 ff ff 3b fb 0f 90 01 05 c7 85 90 01 03 ff 44 4f 53 20 c7 85 90 01 03 ff 45 52 52 4f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}