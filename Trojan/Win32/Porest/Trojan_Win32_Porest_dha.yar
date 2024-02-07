
rule Trojan_Win32_Porest_dha{
	meta:
		description = "Trojan:Win32/Porest!dha,SIGNATURE_TYPE_PEHSTR,03 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {c1 e8 10 33 c2 69 c0 6b ca eb 85 8b c8 c1 e9 0d 33 c8 } //01 00 
		$a_01_1 = {8a 10 00 55 90 01 01 0f b6 4d 90 01 01 8d 8c 0d 90 01 04 8a 19 88 18 88 11 0f b6 00 0f b6 ca 03 c8 81 e1 ff 00 00 00 8a 84 0d 90 01 04 32 04 37 88 06 46 ff 4d 90 01 01 75 bc 90 00 } //01 00 
		$a_01_2 = {8a 19 88 18 88 11 0f b6 00 0f b6 ca 03 c8 81 e1 ff 00 00 00 } //01 00 
		$a_01_3 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 57 69 6e 33 32 3b 20 78 38 36 3b 20 72 76 3a 32 30 2e 30 29 20 47 65 63 6b 6f 2f 32 30 31 30 30 31 30 31 20 46 69 72 65 66 6f 78 2f 32 30 2e 30 } //00 00  Mozilla/5.0 (Windows NT 6.1; Win32; x86; rv:20.0) Gecko/20100101 Firefox/20.0
	condition:
		any of ($a_*)
 
}