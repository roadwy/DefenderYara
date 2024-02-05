
rule Trojan_Win32_Derusbi_B_dha{
	meta:
		description = "Trojan:Win32/Derusbi.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff 75 6c ff 55 54 e9 ca 01 00 00 83 f9 12 75 0c 8b 46 04 81 0e 00 00 04 00 89 46 04 83 f9 11 75 0c 8b 46 04 } //01 00 
		$a_01_1 = {ff 75 6c ff 55 5c 85 c0 75 09 8b 46 04 83 0e 20 89 46 04 8d 45 64 50 8d 85 } //01 00 
		$a_01_2 = {c6 45 60 63 c6 45 61 75 c6 45 62 74 c6 45 63 65 c6 45 64 45 c6 45 65 78 c6 45 66 57 88 5d 67 ff 15 } //01 00 
		$a_01_3 = {33 db 3b c3 75 04 33 c0 eb 1d 8d 4c 24 18 51 33 f6 ff d0 0f b7 44 24 18 83 f8 06 74 05 83 f8 09 75 03 33 f6 } //00 00 
	condition:
		any of ($a_*)
 
}