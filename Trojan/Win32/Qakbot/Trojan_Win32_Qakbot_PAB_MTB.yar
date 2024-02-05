
rule Trojan_Win32_Qakbot_PAB_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 3a c0 90 13 bb 04 00 00 00 53 3a ed 90 13 5e f7 f6 66 3b db 90 13 0f b6 44 15 90 01 01 33 c8 3a c0 90 13 8b 45 90 01 01 88 4c 05 90 01 01 90 13 8b 45 90 01 01 40 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_PAB_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0d 00 00 02 00 "
		
	strings :
		$a_00_0 = {3b fc 87 e7 5e 49 0f a4 d3 37 81 de 9a 0a 00 00 81 fa 1c 1f 00 00 c1 ee 8b f7 e6 f7 ff f7 c4 39 08 00 00 e4 b4 cd 98 69 e4 2f 03 00 00 81 d2 b5 1d 00 00 0f a4 db af } //01 00 
		$a_81_1 = {44 68 57 74 65 63 53 35 32 4c 48 36 67 33 34 2e 64 6c 6c } //01 00 
		$a_81_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00 
		$a_81_3 = {46 6f 6e 6b 49 6b 4e } //01 00 
		$a_81_4 = {4d 71 76 64 45 76 5a 76 } //01 00 
		$a_81_5 = {56 42 46 6a 48 78 46 4f 78 43 } //01 00 
		$a_81_6 = {63 6c 45 78 72 56 71 52 } //01 00 
		$a_81_7 = {6b 4d 55 61 6b } //01 00 
		$a_81_8 = {6b 72 42 56 45 75 57 6a 64 6c } //01 00 
		$a_81_9 = {74 67 57 7a 42 54 } //01 00 
		$a_81_10 = {74 77 48 49 73 } //01 00 
		$a_81_11 = {76 61 6f 62 43 6a } //01 00 
		$a_81_12 = {79 4d 42 65 47 49 } //00 00 
	condition:
		any of ($a_*)
 
}