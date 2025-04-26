
rule Misleading_Win32_Dappeshil{
	meta:
		description = "Misleading:Win32/Dappeshil,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 72 69 76 61 63 79 4d 61 73 74 65 72 5c 62 69 6e 5c 52 65 6c 65 61 73 65 5c 50 43 50 72 69 76 61 63 79 53 68 69 65 6c 64 2e 70 64 62 } //1 PrivacyMaster\bin\Release\PCPrivacyShield.pdb
		$a_01_1 = {67 65 74 5f 49 65 55 73 65 72 50 61 73 73 53 63 61 6e 6e 65 72 } //1 get_IeUserPassScanner
		$a_01_2 = {50 43 50 72 69 76 61 63 79 53 68 69 65 6c 64 2e 65 78 65 } //1 PCPrivacyShield.exe
		$a_01_3 = {53 68 69 65 6c 64 41 70 70 73 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule Misleading_Win32_Dappeshil_2{
	meta:
		description = "Misleading:Win32/Dappeshil,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 65 67 43 6c 65 61 6e 65 72 5c 62 69 6e 5c 52 65 6c 65 61 73 65 5c 50 43 43 6c 65 61 6e 69 6e 67 55 74 69 6c 69 74 79 2e 70 64 62 } //1 RegCleaner\bin\Release\PCCleaningUtility.pdb
		$a_01_1 = {50 43 43 6c 65 61 6e 69 6e 67 55 74 69 6c 69 74 79 2e 65 78 65 } //1 PCCleaningUtility.exe
		$a_01_2 = {67 65 74 5f 46 69 66 74 79 46 69 78 65 64 } //1 get_FiftyFixed
		$a_01_3 = {49 65 53 61 76 65 64 50 61 73 73 77 6f 72 64 53 63 61 6e 6e 65 72 } //1 IeSavedPasswordScanner
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule Misleading_Win32_Dappeshil_3{
	meta:
		description = "Misleading:Win32/Dappeshil,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 65 67 43 6c 65 61 6e 65 72 5c 62 69 6e 5c 52 65 6c 65 61 73 65 5c 50 43 52 65 67 69 73 74 72 79 53 68 69 65 6c 64 2e 70 64 62 } //1 RegCleaner\bin\Release\PCRegistryShield.pdb
		$a_01_1 = {52 65 67 43 6c 65 61 6e 65 72 2e 53 74 61 72 74 75 70 2e 72 65 73 6f 75 72 63 65 73 } //1 RegCleaner.Startup.resources
		$a_01_2 = {50 43 52 65 67 69 73 74 72 79 53 68 69 65 6c 64 2e 65 78 65 } //1 PCRegistryShield.exe
		$a_01_3 = {53 68 69 65 6c 64 41 70 70 73 00 } //1
		$a_01_4 = {67 65 74 5f 46 69 66 74 79 46 69 78 65 64 } //1 get_FiftyFixed
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
rule Misleading_Win32_Dappeshil_4{
	meta:
		description = "Misleading:Win32/Dappeshil,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 65 6c 63 6f 6d 65 20 74 6f 20 74 68 65 20 50 43 20 43 6c 65 61 6e 69 6e 67 20 55 74 69 6c 69 74 79 20 57 69 7a 61 72 64 } //1 Welcome to the PC Cleaning Utility Wizard
		$a_01_1 = {68 74 74 70 3a 2f 2f 73 68 69 65 6c 64 61 70 70 73 2e 63 6f 6d 2f 65 75 6c 61 2f } //1 http://shieldapps.com/eula/
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 50 43 20 43 6c 65 61 6e 69 6e 67 20 55 74 69 6c 69 74 79 } //1 SOFTWARE\PC Cleaning Utility
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 50 43 20 43 6c 65 61 6e 69 6e 67 20 55 74 69 6c 69 74 79 } //1 Software\Microsoft\Windows\CurrentVersion\Uninstall\PC Cleaning Utility
		$a_01_4 = {43 72 65 61 74 65 4d 75 74 65 78 28 69 20 30 2c 20 69 20 30 2c 20 74 20 22 50 43 43 6c 65 61 6e 69 6e 67 55 74 69 6c 69 74 79 53 65 74 75 70 2e 65 78 65 22 29 } //1 CreateMutex(i 0, i 0, t "PCCleaningUtilitySetup.exe")
		$a_01_5 = {6c 61 62 65 6c 6e 61 6d 65 3d 50 43 20 43 6c 65 61 6e 69 6e 67 20 55 74 69 6c 69 74 79 26 61 70 70 76 65 72 3d } //1 labelname=PC Cleaning Utility&appver=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}
rule Misleading_Win32_Dappeshil_5{
	meta:
		description = "Misleading:Win32/Dappeshil,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {57 65 6c 63 6f 6d 65 20 74 6f 20 74 68 65 20 50 43 20 50 72 69 76 61 63 79 20 53 68 69 65 6c 64 20 57 69 7a 61 72 64 } //1 Welcome to the PC Privacy Shield Wizard
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 50 43 20 50 72 69 76 61 63 79 20 53 68 69 65 6c 64 } //1 Software\Microsoft\Windows\CurrentVersion\Uninstall\PC Privacy Shield
		$a_01_2 = {43 72 65 61 74 65 4d 75 74 65 78 28 69 20 30 2c 20 69 20 30 2c 20 74 20 22 50 43 50 72 69 76 61 63 79 53 68 69 65 6c 64 53 65 74 75 70 2e 65 78 65 22 29 } //1 CreateMutex(i 0, i 0, t "PCPrivacyShieldSetup.exe")
		$a_01_3 = {6c 61 62 65 6c 6e 61 6d 65 3d 50 43 20 50 72 69 76 61 63 79 20 53 68 69 65 6c 64 26 61 70 70 76 65 72 3d } //1 labelname=PC Privacy Shield&appver=
		$a_01_4 = {5c 50 43 50 72 69 76 61 63 79 53 68 69 65 6c 64 2e 65 78 65 22 20 73 74 61 72 74 73 63 61 6e } //1 \PCPrivacyShield.exe" startscan
		$a_01_5 = {68 74 74 70 3a 2f 2f 73 68 69 65 6c 64 61 70 70 73 2e 63 6f 6d 2f 65 75 6c 61 2f } //1 http://shieldapps.com/eula/
		$a_01_6 = {53 4f 46 54 57 41 52 45 5c 53 68 69 65 6c 64 41 70 70 73 5c 50 43 20 50 72 69 76 61 63 79 20 53 68 69 65 6c 64 } //1 SOFTWARE\ShieldApps\PC Privacy Shield
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}
rule Misleading_Win32_Dappeshil_6{
	meta:
		description = "Misleading:Win32/Dappeshil,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {57 65 6c 63 6f 6d 65 20 74 6f 20 74 68 65 20 50 43 20 52 65 67 69 73 74 72 79 20 53 68 69 65 6c 64 20 57 69 7a 61 72 64 } //1 Welcome to the PC Registry Shield Wizard
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 50 43 20 52 65 67 69 73 74 72 79 20 53 68 69 65 6c 64 } //1 Software\Microsoft\Windows\CurrentVersion\Uninstall\PC Registry Shield
		$a_01_2 = {43 72 65 61 74 65 4d 75 74 65 78 28 69 20 30 2c 20 69 20 30 2c 20 74 20 22 50 43 52 65 67 69 73 74 72 79 53 68 69 65 6c 64 53 65 74 75 70 2e 65 78 65 22 } //1 CreateMutex(i 0, i 0, t "PCRegistryShieldSetup.exe"
		$a_01_3 = {6c 61 62 65 6c 6e 61 6d 65 3d 50 43 20 52 65 67 69 73 74 72 79 20 53 68 69 65 6c 64 26 61 70 70 76 65 72 3d } //1 labelname=PC Registry Shield&appver=
		$a_01_4 = {5c 50 43 52 65 67 69 73 74 72 79 53 68 69 65 6c 64 2e 65 78 65 22 20 73 74 61 72 74 73 63 61 6e } //1 \PCRegistryShield.exe" startscan
		$a_01_5 = {68 74 74 70 3a 2f 2f 73 68 69 65 6c 64 61 70 70 73 2e 63 6f 6d 2f 65 75 6c 61 2f } //1 http://shieldapps.com/eula/
		$a_01_6 = {53 4f 46 54 57 41 52 45 5c 53 68 69 65 6c 64 41 70 70 73 5c 50 43 20 52 65 67 69 73 74 72 79 20 53 68 69 65 6c 64 } //1 SOFTWARE\ShieldApps\PC Registry Shield
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}