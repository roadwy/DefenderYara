
rule Trojan_Win32_Fraudropper_A_MTB{
	meta:
		description = "Trojan:Win32/Fraudropper.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_81_0 = {56 69 6f 74 74 6f 42 69 6e 64 65 72 5f 53 74 75 62 } //01 00  ViottoBinder_Stub
		$a_81_1 = {7c 76 69 6f 74 74 6f 62 69 6e 64 65 72 7c 7c 76 74 74 62 6e 64 72 7c 4d 5a } //01 00  |viottobinder||vttbndr|MZ
		$a_01_2 = {24 00 37 00 37 00 52 00 65 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //01 00  $77Redownloader.exe
		$a_81_3 = {24 37 37 6d 61 69 6e 31 2e 65 78 65 } //01 00  $77main1.exe
		$a_01_4 = {41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 70 00 61 00 74 00 68 00 } //01 00  Application path
		$a_01_5 = {41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 64 00 61 00 74 00 61 00 } //01 00  Application data
		$a_01_6 = {41 00 70 00 70 00 44 00 61 00 74 00 61 00 } //01 00  AppData
		$a_01_7 = {57 00 69 00 6e 00 44 00 69 00 72 00 } //01 00  WinDir
		$a_01_8 = {32 00 31 00 34 00 37 00 34 00 38 00 33 00 36 00 34 00 38 00 } //00 00  2147483648
	condition:
		any of ($a_*)
 
}