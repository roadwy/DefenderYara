
rule Misleading_Win32_Winfixer{
	meta:
		description = "Misleading:Win32/Winfixer,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {2d 73 74 6f 70 00 00 00 2d 73 74 61 72 74 } //1
		$a_00_1 = {5f 64 65 6c 65 74 65 64 5f } //1 _deleted_
		$a_00_2 = {22 25 73 22 20 2d 73 74 61 72 74 } //1 "%s" -start
		$a_00_3 = {44 65 6c 65 74 65 00 00 4e 6f 52 65 6d 6f 76 65 00 00 00 00 46 6f 72 63 65 52 65 6d 6f 76 65 } //1
		$a_00_4 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //1 OpenProcess
		$a_00_5 = {50 72 6f 63 65 73 73 33 32 4e 65 78 74 } //1 Process32Next
		$a_00_6 = {8b 44 24 04 83 f8 07 77 20 ff 24 85 c0 12 40 00 66 b8 15 00 c3 66 b8 46 00 c3 66 b8 50 00 c3 66 b8 bb 01 c3 66 b8 38 04 c3 66 33 c0 c3 } //1
		$a_02_7 = {68 84 00 00 00 50 8d 4c 24 20 e8 90 01 03 ff 57 68 85 00 00 00 e8 90 01 03 ff 83 c4 08 3b c7 74 0f 68 85 00 00 00 50 8d 4c 24 2c e8 90 01 03 ff 57 68 82 00 00 00 e8 90 01 03 ff 83 c4 08 3b c7 74 0f 68 82 00 00 00 50 8d 4c 24 14 e8 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_02_7  & 1)*1) >=8
 
}
rule Misleading_Win32_Winfixer_2{
	meta:
		description = "Misleading:Win32/Winfixer,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 07 00 00 "
		
	strings :
		$a_01_0 = {8b 86 00 04 00 00 33 db 8a 1f 8b d0 c1 ea 18 c1 e0 08 33 d3 81 e2 ff 00 00 00 33 04 96 47 49 89 86 00 04 00 00 75 d9 } //1
		$a_01_1 = {8b 86 00 04 00 00 0f b6 1f 8b d0 c1 ea 18 33 d3 81 e2 ff 00 00 00 c1 e0 08 33 04 96 47 49 89 86 00 04 00 00 75 da } //1
		$a_01_2 = {6a 04 68 de 00 00 00 68 a1 01 00 00 68 8a 00 00 00 6a 0e } //1
		$a_00_3 = {2f 00 61 00 64 00 2f 00 62 00 6b 00 2f 00 37 00 34 00 31 00 32 00 2d 00 33 00 39 00 36 00 31 00 34 00 2d 00 32 00 30 00 35 00 34 00 2d 00 31 00 30 00 3f 00 73 00 65 00 74 00 75 00 70 00 3d 00 31 00 00 00 } //1
		$a_00_4 = {26 00 6d 00 70 00 75 00 69 00 64 00 3d 00 00 00 } //1
		$a_00_5 = {49 00 4d 00 20 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 00 00 } //1
		$a_00_6 = {70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 5c 00 63 00 6f 00 6f 00 6b 00 69 00 65 00 73 00 34 00 2e 00 64 00 61 00 74 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=4
 
}
rule Misleading_Win32_Winfixer_3{
	meta:
		description = "Misleading:Win32/Winfixer,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 75 70 64 61 74 65 73 2e 77 69 6e 73 6f 66 74 77 61 72 65 2e 63 6f 6d 2f } //1 http://updates.winsoftware.com/
		$a_01_1 = {65 72 72 2e 6c 6f 67 } //1 err.log
		$a_01_2 = {26 70 63 69 64 3d } //1 &pcid=
		$a_01_3 = {2f 70 69 6e 67 2e 70 68 70 } //1 /ping.php
		$a_01_4 = {75 70 2e 64 61 74 } //1 up.dat
		$a_01_5 = {64 65 6c 64 2e 62 61 74 } //1 deld.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Misleading_Win32_Winfixer_4{
	meta:
		description = "Misleading:Win32/Winfixer,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {61 76 61 69 6c 61 62 6c 65 20 66 6f 72 20 64 6f 77 6e 6c 6f 61 64 20 6f 6e 20 72 65 6d 6f 74 65 20 73 65 72 76 65 72 } //1 available for download on remote server
		$a_01_1 = {61 6c 72 65 61 64 79 20 69 6e 73 74 61 6c 6c 65 64 20 6f 6e 20 6c 6f 63 61 6c 20 63 6f 6d 70 75 74 65 72 } //1 already installed on local computer
		$a_01_2 = {43 6f 6e 6e 65 63 74 69 6e 67 20 74 6f 20 73 65 72 76 65 72 2e 2e 2e } //1 Connecting to server...
		$a_01_3 = {75 70 64 61 74 65 72 2e 64 61 74 } //1 updater.dat
		$a_01_4 = {75 70 64 61 74 65 2e 6c 6f 67 } //1 update.log
		$a_01_5 = {44 72 69 76 65 43 6c 65 61 6e 65 72 55 70 64 61 74 65 72 54 65 72 6d 69 6e 61 74 69 6f 6e 45 76 65 6e 74 } //1 DriveCleanerUpdaterTerminationEvent
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Misleading_Win32_Winfixer_5{
	meta:
		description = "Misleading:Win32/Winfixer,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 44 65 75 73 20 43 6c 65 61 6e 65 72 } //1 SOFTWARE\Deus Cleaner
		$a_01_1 = {69 6e 61 63 63 75 72 61 63 79 5f 74 6f 74 61 6c 2e 2e 2e } //1 inaccuracy_total...
		$a_01_2 = {44 43 55 70 64 61 74 65 2e 65 78 65 20 2f 52 } //1 DCUpdate.exe /R
		$a_01_3 = {44 45 55 53 5f 43 4c 45 41 4e 45 52 5f 41 50 50 5f 43 4c 4f 53 45 } //1 DEUS_CLEANER_APP_CLOSE
		$a_01_4 = {44 45 55 53 5f 43 4c 45 41 4e 45 52 5f 53 44 } //1 DEUS_CLEANER_SD
		$a_01_5 = {2a 44 43 2e 6c 6e 67 } //1 *DC.lng
		$a_01_6 = {44 00 65 00 75 00 73 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 } //1 Deus Software
		$a_01_7 = {44 00 65 00 75 00 73 00 20 00 43 00 6c 00 65 00 61 00 6e 00 65 00 72 00 } //1 Deus Cleaner
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule Misleading_Win32_Winfixer_6{
	meta:
		description = "Misleading:Win32/Winfixer,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6c 74 6f } //1 mailto
		$a_01_1 = {5f 73 6f 75 72 63 65 76 73 73 5c 50 72 6f 64 75 63 74 73 5c 70 72 6f 74 6f 74 79 70 65 73 5c 41 64 76 61 6e 63 65 64 43 6c 65 61 6e 65 72 5c 41 44 43 63 77 5c 41 44 43 63 77 5c 52 65 6c 65 61 73 65 5c 41 44 43 63 77 2e 70 64 62 } //1 _sourcevss\Products\prototypes\AdvancedCleaner\ADCcw\ADCcw\Release\ADCcw.pdb
		$a_01_2 = {61 00 64 00 76 00 61 00 6e 00 63 00 65 00 64 00 63 00 6c 00 65 00 61 00 6e 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 } //1 advancedcleaner.com
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Misleading_Win32_Winfixer_7{
	meta:
		description = "Misleading:Win32/Winfixer,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 6f 77 6e 6c 6f 61 64 65 64 00 00 46 69 6c 65 4b 65 79 50 61 69 64 00 43 53 49 44 4c 5f 54 45 4d 50 4c 41 54 45 53 } //1
		$a_01_1 = {2f 70 6e 3d 25 73 20 2f 75 72 6c 3d 25 73 } //1 /pn=%s /url=%s
		$a_01_2 = {61 63 74 6e 5f 61 62 62 72 5f 76 32 } //1 actn_abbr_v2
		$a_01_3 = {47 6c 6f 62 61 6c 00 00 2e 64 61 74 00 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1
		$a_01_4 = {53 61 6c 65 73 4d 6f 6e 69 74 6f 72 00 00 00 00 4e 65 74 49 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //1
		$a_01_5 = {70 72 6f 66 69 6c 65 5c 63 6f 6f 6b 69 65 73 34 2e 64 61 74 } //1 profile\cookies4.dat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}
rule Misleading_Win32_Winfixer_8{
	meta:
		description = "Misleading:Win32/Winfixer,SIGNATURE_TYPE_PEHSTR,2a 00 2a 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //10 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {49 6e 74 65 72 6e 65 74 47 65 74 43 6f 6f 6b 69 65 41 } //10 InternetGetCookieA
		$a_01_2 = {52 65 67 53 65 74 56 61 6c 75 65 45 78 41 } //10 RegSetValueExA
		$a_01_3 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 41 } //10 GetStartupInfoA
		$a_01_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 61 00 64 00 76 00 61 00 6e 00 63 00 65 00 64 00 63 00 6c 00 65 00 61 00 6e 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 } //1 http://advancedcleaner.com
		$a_01_5 = {55 41 44 43 20 3d 20 31 3b 20 65 78 70 69 72 65 73 20 3d 20 20 20 47 4d 54 } //1 UADC = 1; expires =   GMT
		$a_01_6 = {70 72 6f 74 6f 74 79 70 65 73 5c 61 64 76 61 6e 63 65 64 63 6c 65 61 6e 65 72 } //1 prototypes\advancedcleaner
		$a_01_7 = {61 64 76 61 6e 63 65 64 63 6c 65 61 6e 65 72 2e 63 6f 6d 7c 55 41 44 43 } //1 advancedcleaner.com|UADC
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=42
 
}
rule Misleading_Win32_Winfixer_9{
	meta:
		description = "Misleading:Win32/Winfixer,SIGNATURE_TYPE_PEHSTR,03 00 03 00 0b 00 00 "
		
	strings :
		$a_01_0 = {50 00 43 00 50 00 72 00 69 00 76 00 61 00 63 00 79 00 54 00 6f 00 6f 00 6c 00 5c 00 47 00 44 00 43 00 2e 00 65 00 78 00 65 00 } //1 PCPrivacyTool\GDC.exe
		$a_01_1 = {53 00 70 00 79 00 47 00 75 00 61 00 72 00 64 00 50 00 72 00 6f 00 5c 00 44 00 61 00 74 00 5c 00 62 00 6e 00 6c 00 69 00 6e 00 6b 00 2e 00 64 00 61 00 74 00 } //1 SpyGuardPro\Dat\bnlink.dat
		$a_01_2 = {53 00 70 00 79 00 47 00 75 00 61 00 72 00 64 00 50 00 72 00 6f 00 5c 00 70 00 67 00 73 00 2e 00 65 00 78 00 65 00 } //1 SpyGuardPro\pgs.exe
		$a_01_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 63 00 6c 00 65 00 61 00 6e 00 2e 00 73 00 79 00 73 00 74 00 65 00 6d 00 65 00 72 00 72 00 6f 00 72 00 66 00 69 00 78 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 2f 00 4d 00 54 00 67 00 31 00 4d 00 7a 00 45 00 3d 00 2f 00 32 00 2f 00 } //1 http://clean.systemerrorfixer.com/MTg1MzE=/2/
		$a_01_4 = {59 00 6f 00 75 00 72 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00 20 00 68 00 61 00 73 00 20 00 6d 00 75 00 63 00 68 00 20 00 6f 00 66 00 20 00 65 00 72 00 72 00 6f 00 72 00 73 00 21 00 20 00 50 00 6c 00 65 00 61 00 73 00 65 00 20 00 63 00 6c 00 69 00 63 00 6b 00 20 00 6f 00 6e 00 20 00 74 00 68 00 65 00 20 00 62 00 75 00 74 00 74 00 6f 00 6e 00 20 00 62 00 65 00 6c 00 6f 00 77 00 20 00 74 00 6f 00 20 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 20 00 61 00 6e 00 64 00 20 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 20 00 74 00 68 00 65 00 20 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 20 00 74 00 6f 00 20 00 46 00 69 00 78 00 20 00 54 00 68 00 65 00 6d 00 21 00 } //1 Your System has much of errors! Please click on the button below to download and install the software to Fix Them!
		$a_01_5 = {68 74 74 70 3a 2f 2f 70 72 6f 74 65 63 74 2e 73 70 79 67 75 61 72 64 70 72 6f 2e 63 6f 6d 2f 4d 54 6b 79 4e 44 45 3d 2f 32 2f } //1 http://protect.spyguardpro.com/MTkyNDE=/2/
		$a_01_6 = {59 6f 75 72 20 73 79 73 74 65 6d 20 69 73 20 69 6e 66 65 63 74 65 64 20 77 69 74 68 20 73 70 79 77 61 72 65 2c 20 70 72 6f 74 65 63 74 69 6f 6e 20 6c 65 76 65 6c 20 69 73 20 63 72 69 74 69 63 61 6c 79 20 6c 6f 77 2e } //1 Your system is infected with spyware, protection level is criticaly low.
		$a_01_7 = {68 74 74 70 3a 2f 2f 70 72 6f 74 65 63 74 2e 61 64 76 61 6e 63 65 64 63 6c 65 61 6e 65 72 2e 63 6f 6d 2f 4d 6a 59 35 4d 77 3d 3d 2f 32 2f } //1 http://protect.advancedcleaner.com/MjY5Mw==/2/
		$a_01_8 = {74 74 70 3a 2f 2f 70 2f 28 63 74 2e 61 37 70 32 } //1 ttp://p/(ct.a7p2
		$a_01_9 = {59 35 4d 77 3d 3d 2f 32 2f 38 33 30 2f 61 78 3d } //1 Y5Mw==/2/830/ax=
		$a_01_10 = {21 2e 6c 6e 6b 2b 25 57 42 6e } //1 !.lnk+%WBn
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=3
 
}