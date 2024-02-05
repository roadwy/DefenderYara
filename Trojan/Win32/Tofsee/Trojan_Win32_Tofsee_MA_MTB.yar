
rule Trojan_Win32_Tofsee_MA_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {70 6c 6b 64 65 6b 6a 79 6e 68 61 64 65 66 72 64 65 72 61 74 61 66 72 68 6e 61 6d 6b 69 6f 70 6c } //05 00 
		$a_01_1 = {61 66 64 65 72 74 61 79 75 6e 6d 62 67 64 65 72 74 67 66 00 61 63 6c 65 64 69 74 2e 64 6c 6c } //05 00 
		$a_01_2 = {79 75 6f 6d 6d 79 69 65 66 70 61 65 6f 77 62 67 6e } //02 00 
		$a_01_3 = {8b 08 83 e8 fc f7 d9 83 e9 29 83 c1 fe 8d 49 01 29 d1 31 d2 4a 21 ca c7 47 00 00 00 00 00 31 0f 83 c7 04 83 ee 04 83 fe 00 75 } //00 00 
	condition:
		any of ($a_*)
 
}