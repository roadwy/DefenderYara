
rule Trojan_Win32_Sefesev_A{
	meta:
		description = "Trojan:Win32/Sefesev.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 61 66 78 2e 65 78 65 00 5c 73 76 63 00 } //01 00  愀硦攮數尀癳c
		$a_03_1 = {8a 47 01 47 84 c0 75 f8 a1 90 01 02 40 00 8b 0d 90 01 02 40 00 6a 00 89 07 68 90 01 02 40 00 89 4f 04 ff 15 90 01 02 40 00 8b 15 90 01 02 40 00 68 00 52 03 00 81 c2 75 0f 00 00 8b f0 52 56 ff 15 90 01 02 40 00 56 ff 15 90 01 02 40 00 90 00 } //01 00 
		$a_03_2 = {6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 68 90 01 02 40 00 ff 15 90 01 02 40 00 68 e8 03 00 00 ff 15 90 01 02 40 00 6a 00 ff 15 90 01 02 40 00 90 00 } //01 00 
		$a_03_3 = {8a 08 40 84 c9 75 f9 56 57 2b c2 bf 90 01 02 40 00 88 88 90 01 02 40 00 4f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}