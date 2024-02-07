
rule PWS_Win32_Fareit_VK_MTB{
	meta:
		description = "PWS:Win32/Fareit.VK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //01 00  MSVBVM60.DLL
		$a_02_1 = {58 52 81 ca 90 01 04 5a 51 81 f1 90 01 04 59 8f 04 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule PWS_Win32_Fareit_VK_MTB_2{
	meta:
		description = "PWS:Win32/Fareit.VK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //01 00  MSVBVM60.DLL
		$a_02_1 = {8f 04 18 16 17 eb 90 09 03 00 83 c4 90 00 } //01 00 
		$a_02_2 = {31 34 24 68 90 09 03 00 83 c4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule PWS_Win32_Fareit_VK_MTB_3{
	meta:
		description = "PWS:Win32/Fareit.VK!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //01 00  MSVBVM60.DLL
		$a_01_1 = {5f 8b 10 53 } //01 00 
		$a_01_2 = {5b 31 f2 57 } //01 00 
		$a_01_3 = {5f 89 10 57 } //01 00 
		$a_01_4 = {8b 9c 24 1c 01 00 00 } //01 00 
		$a_01_5 = {8b 94 24 20 01 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}