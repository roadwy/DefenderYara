
rule Trojan_Win32_Emotet_CA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b f8 33 d2 8b c3 f7 f1 8b ce 52 e8 90 01 04 8a 00 30 07 43 3b 5d 20 72 90 00 } //01 00 
		$a_02_1 = {33 d2 f7 f1 52 8b 4d 1c e8 90 01 04 8b 55 e8 8a 0a 32 08 8b 55 e8 88 0a eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_CA_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 03 00 "
		
	strings :
		$a_81_0 = {30 43 6e 4f 28 57 4d 55 28 4b 63 35 53 51 78 6c 38 42 75 23 52 2a 6a 56 59 30 41 41 4b 53 67 39 73 39 4f 55 34 4e 5e 2b 78 43 36 5a 73 2b } //03 00 
		$a_81_1 = {52 65 73 74 72 69 63 74 52 75 6e } //03 00 
		$a_81_2 = {4e 6f 4e 65 74 43 6f 6e 6e 65 63 74 44 69 73 63 6f 6e 6e 65 63 74 } //03 00 
		$a_81_3 = {4e 6f 52 65 63 65 6e 74 44 6f 63 73 48 69 73 74 6f 72 79 } //03 00 
		$a_81_4 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_CA_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.CA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 e3 c8 20 6e 3b 31 d8 89 d3 c1 e3 19 c1 fb 1f 81 e3 90 41 dc 76 31 d8 c1 e2 18 c1 fa 1f 81 e2 20 83 b8 ed 31 d0 0f b6 11 41 85 d2 0f } //01 00 
		$a_01_1 = {8b 06 01 d8 8b 55 e4 30 10 43 8b 06 3b 58 f4 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_CA_MTB_4{
	meta:
		description = "Trojan:Win32/Emotet.CA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {c1 e1 1c c1 f9 1f 81 e1 32 88 db 0e 33 c1 } //01 00 
		$a_01_1 = {c1 e1 1a c1 f9 1f 81 e1 c8 20 6e 3b 33 c1 } //01 00 
		$a_01_2 = {8b 01 ba ff fe fe 7e 03 d0 83 f0 ff 33 c2 83 c1 04 a9 00 01 01 81 74 e8 8b 41 fc 84 c0 74 32 } //01 00 
		$a_01_3 = {ff e0 5f 5e 5b c9 c2 08 00 58 59 87 04 24 ff e0 58 59 87 04 24 ff e0 } //00 00 
	condition:
		any of ($a_*)
 
}