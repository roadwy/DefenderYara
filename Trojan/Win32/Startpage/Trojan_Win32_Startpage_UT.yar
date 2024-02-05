
rule Trojan_Win32_Startpage_UT{
	meta:
		description = "Trojan:Win32/Startpage.UT,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {40 c1 e0 02 2b e0 8d 3c 24 51 c7 45 fc 01 00 00 00 8d 75 08 8b 1e 83 c6 04 51 e8 } //01 00 
		$a_00_1 = {68 74 74 70 3a 2f 2f 6a 6d 70 2e 6e 65 74 2e 63 6e 2f 3f } //01 00 
		$a_00_2 = {53 74 61 72 74 20 50 61 67 65 } //01 00 
		$a_02_3 = {2e 6c 6e 6b 90 02 04 68 61 6f 31 32 33 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}