
rule Trojan_Win32_Tevesogu_A{
	meta:
		description = "Trojan:Win32/Tevesogu.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 54 56 54 2e 00 } //01 00  吀呖.
		$a_01_1 = {00 00 77 00 69 00 6e 00 73 00 74 00 61 00 30 00 5c 00 64 00 65 00 66 00 61 00 75 00 6c 00 74 00 00 00 } //01 00 
		$a_01_2 = {52 00 55 00 4e 00 44 00 4c 00 4c 00 33 00 32 00 2e 00 45 00 58 00 45 00 00 00 00 00 52 00 55 00 4e 00 41 00 53 00 00 00 } //01 00 
		$a_01_3 = {00 00 72 00 75 00 6e 00 61 00 73 00 00 00 } //01 00 
		$a_03_4 = {6a 00 6a 00 6a 04 6a 00 6a 01 68 00 00 00 40 68 90 01 02 03 10 68 90 01 04 6a 16 68 90 01 02 03 10 8d 4d ec e8 90 01 02 00 00 8b c8 e8 90 01 02 ff ff 50 ff 15 90 01 02 03 10 89 45 f8 8d 4d ec e8 90 01 02 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}