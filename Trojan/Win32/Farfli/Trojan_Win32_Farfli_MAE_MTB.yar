
rule Trojan_Win32_Farfli_MAE_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {89 46 24 8b 4e 08 68 68 9c 00 10 51 ff d7 } //01 00 
		$a_00_1 = {89 46 70 8b 56 08 68 3c 9b 00 10 52 ff d7 89 46 74 8b 46 08 68 30 9b 00 10 50 ff d7 } //01 00 
		$a_01_2 = {44 6c 6c 55 70 64 61 74 65 } //01 00  DllUpdate
		$a_01_3 = {53 65 72 76 69 63 65 4d 61 69 6e } //01 00  ServiceMain
		$a_01_4 = {55 6e 69 6e 73 74 61 6c 6c } //01 00  Uninstall
		$a_01_5 = {4d 61 69 6e 44 6c 6c 2e 64 6c 6c } //01 00  MainDll.dll
		$a_01_6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 68 6f 73 74 } //01 00  SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost
		$a_01_7 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //00 00  CreateToolhelp32Snapshot
	condition:
		any of ($a_*)
 
}