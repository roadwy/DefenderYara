
rule PWS_Win32_Lineage_CK{
	meta:
		description = "PWS:Win32/Lineage.CK,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {89 11 b0 d8 88 41 04 8b 54 24 04 8d 4c 24 04 51 52 6a 05 68 90 01 03 10 ff d6 90 00 } //01 00 
		$a_01_1 = {ff d6 ff d0 5e 61 e9 } //02 00 
		$a_03_2 = {51 6a 05 8d 55 d4 52 56 8b 7d 2c 8b 07 50 ff 15 90 01 02 00 10 85 c0 0f 84 90 01 02 00 00 83 bd 90 01 03 ff 05 0f 85 90 00 } //01 00 
		$a_01_3 = {48 6f 6f 6b 47 61 6d 65 00 } //01 00 
		$a_01_4 = {4c 69 6e 65 41 67 65 32 42 65 65 2e 64 6c 6c } //00 00  LineAge2Bee.dll
	condition:
		any of ($a_*)
 
}