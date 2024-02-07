
rule Trojan_Win32_Redcap_BA_MSR{
	meta:
		description = "Trojan:Win32/Redcap.BA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {48 70 73 67 68 73 65 72 68 73 65 69 6f 68 69 6a 73 } //02 00  Hpsghserhseiohijs
		$a_01_1 = {4f 6f 73 67 6f 69 77 73 65 6a 68 6f 69 65 6a 68 } //02 00  Oosgoiwsejhoiejh
		$a_01_2 = {57 65 6f 69 67 6a 6f 73 69 6a 68 73 65 6a 69 68 } //02 00  Weoigjosijhsejih
		$a_01_3 = {4b 44 58 4b 68 68 6c 4d 52 50 74 55 77 59 59 46 78 72 41 56 76 4f 46 4f } //02 00  KDXKhhlMRPtUwYYFxrAVvOFO
		$a_01_4 = {6f 4b 63 49 5a 77 42 71 5a 47 4c 70 53 45 6e 74 63 46 4a 65 55 55 4c 56 69 64 4a 78 4e } //02 00  oKcIZwBqZGLpSEntcFJeUULVidJxN
		$a_01_5 = {4b 78 57 58 69 76 77 66 43 6d 75 4e 64 76 70 4d 69 6d 53 45 67 73 71 65 62 55 75 7a } //02 00  KxWXivwfCmuNdvpMimSEgsqebUuz
		$a_01_6 = {4e 47 56 53 58 48 52 75 5a 6d 4d 62 79 72 76 57 77 77 } //00 00  NGVSXHRuZmMbyrvWww
	condition:
		any of ($a_*)
 
}