
rule Trojan_Win32_Zusy_EC_MTB{
	meta:
		description = "Trojan:Win32/Zusy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 06 00 "
		
	strings :
		$a_01_0 = {8b 4d 10 8b 55 14 80 3a 00 74 f8 90 90 90 90 ac 32 02 aa 90 90 90 90 42 49 85 c9 75 e9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zusy_EC_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 4f 52 4b 5f 32 30 31 36 30 33 32 38 31 37 35 36 30 30 37 36 31 39 34 33 } //01 00  WORK_20160328175600761943
		$a_01_1 = {63 3a 5c 5c 44 65 73 74 72 6f } //01 00  c:\\Destro
		$a_81_2 = {6f 74 68 69 6e 66 } //01 00  othinf
		$a_81_3 = {4e 6b 47 79 56 69 41 4a 6b 77 48 69 4c 47 } //01 00  NkGyViAJkwHiLG
		$a_81_4 = {41 4a 6b 77 48 69 4c 47 59 } //00 00  AJkwHiLGY
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zusy_EC_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {56 48 4a 70 59 57 77 67 63 47 56 79 61 57 39 6b 49 47 68 68 63 79 42 6c 65 48 42 70 63 6d 56 6b 4c 67 3d 3d } //01 00  VHJpYWwgcGVyaW9kIGhhcyBleHBpcmVkLg==
		$a_81_1 = {51 32 68 70 62 47 74 68 64 45 4a 31 62 6d 52 73 5a 51 3d 3d } //01 00  Q2hpbGthdEJ1bmRsZQ==
		$a_81_2 = {54 55 46 4a 54 41 3d 3d } //01 00  TUFJTA==
		$a_81_3 = {51 32 68 70 62 47 74 68 64 45 31 68 61 57 77 3d } //01 00  Q2hpbGthdE1haWw=
		$a_01_4 = {49 4e 4a 45 43 54 5f 45 4e 4a 4f 59 45 52 53 2e 70 64 62 } //00 00  INJECT_ENJOYERS.pdb
	condition:
		any of ($a_*)
 
}