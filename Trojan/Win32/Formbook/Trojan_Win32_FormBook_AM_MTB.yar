
rule Trojan_Win32_FormBook_AM_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc } //03 00 
		$a_01_1 = {89 45 f4 6a 40 68 00 30 00 00 8b 55 f4 52 6a 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_FormBook_AM_MTB_2{
	meta:
		description = "Trojan:Win32/FormBook.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {31 45 fc 33 c5 50 89 65 e8 ff 75 f8 8b 45 fc c7 45 fc fe ff ff ff 89 45 f8 8d 45 f0 } //03 00 
		$a_01_1 = {83 c4 08 89 45 f0 6a 40 68 00 30 00 00 8b 4d f4 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_FormBook_AM_MTB_3{
	meta:
		description = "Trojan:Win32/FormBook.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 00 8b 04 88 2d d6 4b 04 00 41 } //02 00 
		$a_01_1 = {88 04 33 43 81 fb 6c 07 00 00 7c ef } //02 00 
		$a_01_2 = {53 69 6d 70 53 68 61 6e 67 68 61 69 } //02 00  SimpShanghai
		$a_01_3 = {48 61 72 71 75 65 62 75 73 65 73 } //00 00  Harquebuses
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_FormBook_AM_MTB_4{
	meta:
		description = "Trojan:Win32/FormBook.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 00 69 00 62 00 6d 00 63 00 45 00 4f 00 77 00 51 00 4b 00 4f 00 57 00 72 00 74 00 67 00 31 00 65 00 67 00 45 00 4d 00 74 00 70 00 59 00 4f 00 42 00 41 00 57 00 79 00 46 00 4d 00 77 00 47 00 56 00 65 00 46 00 52 00 4b 00 36 00 35 00 } //01 00  uibmcEOwQKOWrtg1egEMtpYOBAWyFMwGVeFRK65
		$a_01_1 = {6f 00 6a 00 52 00 74 00 64 00 58 00 50 00 32 00 72 00 50 00 4e 00 46 00 35 00 74 00 6c 00 4f 00 49 00 4b 00 6a 00 54 00 4d 00 52 00 68 00 67 00 35 00 58 00 62 00 63 00 41 00 4c 00 61 00 68 00 6e 00 77 00 4e 00 57 00 59 00 32 00 30 00 36 00 } //01 00  ojRtdXP2rPNF5tlOIKjTMRhg5XbcALahnwNWY206
		$a_01_2 = {50 00 61 00 59 00 4e 00 75 00 34 00 52 00 7a 00 38 00 74 00 4e 00 79 00 57 00 5a 00 48 00 43 00 47 00 69 00 72 00 49 00 4a 00 6e 00 50 00 58 00 37 00 39 00 55 00 49 00 5a 00 32 00 33 00 34 00 } //01 00  PaYNu4Rz8tNyWZHCGirIJnPX79UIZ234
		$a_00_3 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //00 00  MSVBVM60.DLL
	condition:
		any of ($a_*)
 
}