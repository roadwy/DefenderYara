
rule Worm_Win32_VB_JK{
	meta:
		description = "Worm:Win32/VB.JK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 90 02 20 6d 00 6f 00 72 00 74 00 65 00 7a 00 61 00 5f 00 90 00 } //01 00 
		$a_01_1 = {73 68 65 6c 6c 5c 65 78 70 6c 6f 72 65 5c 43 6f 6d 6d 61 6e 64 3d 69 72 61 6e 2e 65 78 65 20 45 58 50 4c 4f 52 45 } //01 00  shell\explore\Command=iran.exe EXPLORE
		$a_01_2 = {53 00 74 00 61 00 72 00 74 00 20 00 4d 00 65 00 6e 00 75 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 5c 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 5c 00 77 00 69 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 } //00 00  Start Menu\Programs\Startup\winlogon.exe
	condition:
		any of ($a_*)
 
}