
rule Backdoor_Win32_Lybsus_A{
	meta:
		description = "Backdoor:Win32/Lybsus.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 00 53 00 4e 00 43 00 4f 00 4e 00 54 00 41 00 43 00 54 00 } //01 00  MSNCONTACT
		$a_00_1 = {47 00 45 00 54 00 43 00 4c 00 49 00 50 00 } //01 00  GETCLIP
		$a_01_2 = {74 6d 72 43 61 6d 53 74 61 72 74 } //01 00  tmrCamStart
		$a_00_3 = {5c 00 55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 62 00 61 00 74 00 } //00 00  \Uninstall.bat
	condition:
		any of ($a_*)
 
}