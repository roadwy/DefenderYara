
rule Trojan_Win32_Kutaki_MA_MTB{
	meta:
		description = "Trojan:Win32/Kutaki.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {9b 0b 88 26 08 99 7a 52 37 5c 47 c1 33 4c 5a 7e cf 01 91 04 b8 65 85 38 b9 41 d2 8a 46 8c 86 f8 2b 1c a9 bc a0 5c c8 35 9d bc 6a de 77 43 09 b4 } //01 00 
		$a_01_1 = {53 00 48 00 41 00 44 00 4f 00 } //01 00 
		$a_01_2 = {6d 75 66 75 63 6b 72 } //01 00 
		$a_01_3 = {5b 00 20 00 41 00 4c 00 54 00 44 00 4f 00 57 00 4e 00 20 00 5d 00 } //01 00 
		$a_01_4 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 69 00 6d 00 } //00 00 
	condition:
		any of ($a_*)
 
}