
rule Trojan_Win32_Fareit_VP_MTB{
	meta:
		description = "Trojan:Win32/Fareit.VP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 15 90 01 04 a1 90 01 04 c7 45 08 90 01 04 81 45 08 90 01 04 69 c0 90 01 04 03 45 08 6a 90 01 01 a3 90 01 04 6a 90 01 01 c1 e8 90 01 01 30 04 3e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_VP_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.VP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 74 1d ff 8b c6 83 c0 90 01 01 83 e8 90 01 01 73 90 01 09 8b 04 24 e8 90 01 04 8d 44 18 ff 50 8d 46 0e b9 90 01 04 99 f7 f9 83 c2 90 01 01 58 88 10 43 4f 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_VP_MTB_3{
	meta:
		description = "Trojan:Win32/Fareit.VP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 4d fc 8b 45 08 8b 00 83 45 fc 90 01 01 8d 14 08 8a 4a 03 8a c1 8a d9 80 e1 90 01 01 24 90 01 01 c0 e1 90 01 01 0a 0a c0 e0 90 01 01 0a 42 01 c0 e3 90 01 01 0a 5a 02 88 0c 3e 8b 4d fc 46 88 04 3e 8b 45 0c 46 88 1c 3e 46 3b 08 72 90 00 } //01 00 
		$a_02_1 = {50 56 56 ff 15 90 01 04 e8 90 01 04 30 04 1f 4f 79 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_VP_MTB_4{
	meta:
		description = "Trojan:Win32/Fareit.VP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 45 fc 0f b6 5c 38 ff 0f b6 c3 83 e0 90 01 01 85 c0 75 90 01 01 8d 45 ec 0f b6 d3 2b 55 f4 e8 90 01 04 8b 55 ec 8d 45 f8 e8 90 01 04 eb 90 01 01 8d 45 e8 0f b6 d3 03 55 f4 e8 90 01 04 8b 55 e8 8d 45 f8 e8 90 01 04 47 4e 75 90 00 } //01 00 
		$a_02_1 = {8b 55 f4 8b 45 f8 e8 90 01 04 8b d8 4b 83 fb 90 01 01 75 90 01 12 8b 45 f0 8b 00 8d 04 b0 8b 55 f4 e8 90 01 04 eb 90 01 01 8b 45 f0 8b 00 8d 04 b0 50 8b cb ba 90 01 04 8b 45 f4 e8 90 01 04 8b 45 f8 85 c0 74 90 01 01 83 e8 90 01 01 8b 00 8d 0c 18 8d 45 f4 ba 90 01 04 e8 90 01 04 46 83 7d f4 90 01 01 75 90 00 } //02 00 
		$a_02_2 = {8d 45 f0 50 8b c7 48 8b d0 03 d2 42 b9 90 01 04 8b 45 fc e8 90 01 04 8b 4d f0 8d 45 f4 ba 90 01 04 e8 90 01 04 8b 45 f4 e8 90 01 04 8b d0 8d 45 f8 e8 90 01 04 8b 55 f8 8b c6 e8 90 01 04 47 4b 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}