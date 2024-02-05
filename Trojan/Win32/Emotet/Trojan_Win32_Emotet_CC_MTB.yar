
rule Trojan_Win32_Emotet_CC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 03 00 "
		
	strings :
		$a_81_0 = {23 4c 36 62 4f 59 4f 3e 49 55 32 3e 63 53 34 32 47 49 59 75 46 79 4a 44 26 47 32 49 63 24 4a 43 2b 44 5e 6d 4d 36 4a 6d 39 62 76 63 31 44 63 4b 36 } //03 00 
		$a_81_1 = {43 72 65 61 74 65 53 74 64 41 63 63 65 73 73 69 62 6c 65 4f 62 6a 65 63 74 } //03 00 
		$a_81_2 = {4e 6f 52 65 63 65 6e 74 44 6f 63 73 48 69 73 74 6f 72 79 } //03 00 
		$a_81_3 = {46 69 6e 64 52 65 73 6f 75 72 63 65 41 } //03 00 
		$a_81_4 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_CC_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 e1 32 88 db 0e 33 c1 8b 55 ec c1 e2 1b c1 fa 1f 81 e2 64 10 b7 1d 33 c2 8b 4d ec c1 e1 1a c1 f9 1f 81 e1 c8 20 6e 3b 33 c1 8b 55 ec c1 e2 19 c1 fa 1f 81 e2 90 01 01 41 dc 76 33 c2 8b 4d ec c1 e1 18 c1 f9 1f 81 e1 20 83 b8 ed 33 c1 90 00 } //01 00 
		$a_02_1 = {20 83 b8 ed c7 45 90 01 02 41 dc 76 c7 45 90 01 01 c8 20 6e 3b c7 45 90 01 01 64 10 b7 1d c7 45 90 01 01 32 88 db 0e c7 45 90 01 01 19 c4 6d 07 c7 45 90 01 01 2c 61 0e ee c7 45 90 01 01 96 30 07 77 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}