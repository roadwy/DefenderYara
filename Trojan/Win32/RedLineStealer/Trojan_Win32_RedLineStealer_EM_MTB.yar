
rule Trojan_Win32_RedLineStealer_EM_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {69 c9 98 09 00 00 81 e1 ff 00 00 00 8b 55 0c 03 55 dc 0f b6 02 33 c1 8b 4d 0c 03 4d dc 88 01 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_RedLineStealer_EM_MTB_2{
	meta:
		description = "Trojan:Win32/RedLineStealer.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 06 00 "
		
	strings :
		$a_01_0 = {0f be 04 10 6b c0 44 99 b9 12 00 00 00 f7 f9 8b 55 0c 03 55 fc 0f b6 0a 33 c8 8b 55 0c 03 55 fc 88 0a } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_RedLineStealer_EM_MTB_3{
	meta:
		description = "Trojan:Win32/RedLineStealer.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {b9 41 00 00 00 f7 f9 8b 45 08 0f be 0c 10 81 e1 ff 00 00 00 8b 55 0c 03 55 dc 0f b6 02 33 c1 8b 4d 0c 03 4d dc 88 01 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_RedLineStealer_EM_MTB_4{
	meta:
		description = "Trojan:Win32/RedLineStealer.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 07 00 "
		
	strings :
		$a_01_0 = {96 4b 27 81 db 93 00 00 00 2b f7 87 d2 f7 ea 27 83 e7 62 0b ff 87 da } //07 00 
		$a_01_1 = {97 f7 d8 f8 25 89 00 00 00 8b ff 93 40 2f 83 ea 45 8b c7 87 d3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_RedLineStealer_EM_MTB_5{
	meta:
		description = "Trojan:Win32/RedLineStealer.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 04 00 "
		
	strings :
		$a_01_0 = {29 c3 89 d8 c0 c0 02 83 f0 62 83 e8 0e f7 d0 d0 c8 88 44 15 c1 } //02 00 
		$a_01_1 = {6e 75 72 74 6f 79 63 6b 74 6f 71 6f 58 52 4a 57 51 4f 52 4a 56 6f 71 77 6a 72 69 78 6e 71 77 69 72 6f 6b 76 4a 45 4f 57 54 4e 4d 78 6f 77 65 74 6b 6f 6e 77 76 6f } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_RedLineStealer_EM_MTB_6{
	meta:
		description = "Trojan:Win32/RedLineStealer.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 61 71 62 68 7a 75 70 66 6d 7a 71 } //01 00 
		$a_01_1 = {6d 73 78 6e 74 78 6a 76 69 6e 6d 76 71 73 64 69 74 79 69 71 6e 6a 76 65 6f 6b 65 74 71 7a 65 76 72 6c 69 62 76 72 74 69 68 62 73 6b 71 73 64 78 73 67 6f 71 72 6b 6f 61 69 66 6b 69 71 62 } //01 00 
		$a_01_2 = {6b 73 72 79 79 74 76 64 6d 6b 6b 61 78 78 6f 7a 6c 75 77 71 73 77 61 75 6a 6d 6c 6b 74 6b 70 66 70 6a 70 6c 77 66 6f 6e 72 6a 62 78 70 69 66 64 6d 66 70 6c 6d 69 6e 74 7a } //01 00 
		$a_01_3 = {68 75 6c 69 66 73 66 73 71 6e 6c 71 66 67 78 75 77 71 6b 68 74 6b 79 67 75 6f 73 69 } //01 00 
		$a_01_4 = {43 72 65 61 74 65 46 69 6c 65 41 } //00 00 
	condition:
		any of ($a_*)
 
}