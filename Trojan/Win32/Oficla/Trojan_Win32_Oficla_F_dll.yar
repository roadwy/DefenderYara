
rule Trojan_Win32_Oficla_F_dll{
	meta:
		description = "Trojan:Win32/Oficla.F!dll,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 5c 3f 5c 67 6c 6f 62 61 6c 72 6f 6f 74 5c 73 79 73 74 65 6d 72 6f 6f 74 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 00 } //01 00  屜尿汧扯污潲瑯獜獹整牭潯屴祳瑳浥㈳摜楲敶獲敜捴桜獯t
		$a_03_1 = {56 56 56 8d 45 fc 50 89 75 fc ff 15 90 01 02 00 10 85 c0 74 16 56 56 68 90 01 02 00 10 68 90 01 02 00 10 56 e8 90 01 04 85 c0 74 0d 68 90 01 04 ff 15 90 01 02 00 10 eb c9 33 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}