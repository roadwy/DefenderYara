
rule Trojan_Win32_FormBook_AH_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 03 00 "
		
	strings :
		$a_01_0 = {81 eb 86 d9 00 00 58 bb a2 ae 00 00 f7 d2 40 40 f7 d2 81 f3 96 24 01 00 81 eb f4 75 00 00 81 e1 d3 6f 00 00 b8 30 51 00 00 59 81 e1 c7 2d 01 00 48 3d 40 9c 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_FormBook_AH_MTB_2{
	meta:
		description = "Trojan:Win32/FormBook.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {66 0f 58 c1 90 02 10 66 0f 74 c1 90 02 10 66 0f 6e e6 90 02 10 66 0f 6e e9 90 02 10 0f 57 ec 90 02 10 66 0f 7e e9 90 02 10 39 c1 90 02 10 90 13 0f 77 90 02 10 46 90 02 10 8b 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_FormBook_AH_MTB_3{
	meta:
		description = "Trojan:Win32/FormBook.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {71 75 74 72 62 6c 76 68 6e 6f } //03 00  qutrblvhno
		$a_01_1 = {73 67 74 79 69 68 } //03 00  sgtyih
		$a_01_2 = {74 7a 67 79 6f 62 7a 66 71 } //03 00  tzgyobzfq
		$a_01_3 = {49 6d 6d 52 65 67 69 73 74 65 72 57 6f 72 64 57 } //03 00  ImmRegisterWordW
		$a_01_4 = {49 6d 6d 47 65 74 43 6f 6e 76 65 72 73 69 6f 6e 53 74 61 74 75 73 } //03 00  ImmGetConversionStatus
		$a_01_5 = {49 6d 6d 44 65 73 74 72 6f 79 43 6f 6e 74 65 78 74 } //00 00  ImmDestroyContext
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_FormBook_AH_MTB_4{
	meta:
		description = "Trojan:Win32/FormBook.AH!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {88 14 08 8b 45 e4 8b 4d d4 8a 14 08 80 c2 01 88 14 08 8b 45 e4 8b 4d d4 0f b6 34 08 89 f3 83 f3 36 88 1c 08 8b 45 e4 8b 4d d4 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_FormBook_AH_MTB_5{
	meta:
		description = "Trojan:Win32/FormBook.AH!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 55 d4 8b 52 04 89 14 24 c7 44 24 04 00 00 00 80 c7 44 24 08 01 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 10 03 00 00 00 c7 44 24 14 80 00 00 00 c7 44 24 18 00 00 00 00 89 4d cc ff d0 83 ec 1c } //05 00 
		$a_01_1 = {64 a1 30 00 00 00 8b 40 0c 8b 40 14 8b 00 8b 00 8b 40 10 c3 } //00 00 
	condition:
		any of ($a_*)
 
}