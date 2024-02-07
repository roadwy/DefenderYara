
rule Backdoor_Win32_IISBackdoor_A{
	meta:
		description = "Backdoor:Win32/IISBackdoor.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {49 49 53 5f 62 61 63 6b 64 6f 6f 72 5f 64 6c 6c 2e 64 6c 6c } //03 00  IIS_backdoor_dll.dll
		$a_01_1 = {49 49 53 2d 42 61 63 6b 64 6f 6f 72 2e } //01 00  IIS-Backdoor.
		$a_01_2 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 63 72 65 64 73 2e 64 62 } //01 00  C:\Windows\Temp\creds.db
		$a_01_3 = {43 48 74 74 70 4d 6f 64 75 6c 65 3a 3a 4f 6e 50 6f 73 74 42 65 67 69 6e 52 65 71 75 65 73 74 } //01 00  CHttpModule::OnPostBeginRequest
		$a_01_4 = {58 2d 50 61 73 73 77 6f 72 64 } //01 00  X-Password
		$a_01_5 = {4e 6f 20 43 72 65 64 73 20 46 6f 75 6e 64 } //00 00  No Creds Found
	condition:
		any of ($a_*)
 
}