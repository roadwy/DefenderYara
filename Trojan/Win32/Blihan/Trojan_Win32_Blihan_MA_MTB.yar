
rule Trojan_Win32_Blihan_MA_MTB{
	meta:
		description = "Trojan:Win32/Blihan.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 05 00 "
		
	strings :
		$a_03_0 = {8a 14 28 30 14 31 40 41 3d 80 00 00 00 7c 90 01 01 33 c0 3b cf 7c 90 00 } //05 00 
		$a_01_1 = {56 8b 74 24 0c 57 8b 7c 24 0c 2b f7 8d 0c 17 42 8a 04 0e 4a 88 01 49 85 d2 77 f5 } //01 00 
		$a_01_2 = {70 6f 6d 64 66 67 68 72 74 } //01 00 
		$a_01_3 = {57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 4f 4e } //01 00 
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //00 00 
	condition:
		any of ($a_*)
 
}