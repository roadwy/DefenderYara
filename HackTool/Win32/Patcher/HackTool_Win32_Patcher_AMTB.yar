
rule HackTool_Win32_Patcher_AMTB{
	meta:
		description = "HackTool:Win32/Patcher!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 69 61 4c 6f 67 2a 65 7a 74 } //1 DiaLog*ezt
		$a_01_1 = {78 78 50 7a 72 67 6d 7a } //1 xxPzrgmz
		$a_01_2 = {4e 47 20 50 72 61 63 6b 77 3e 34 49 64 40 2d } //1 NG Prackw>4Id@-
		$a_80_3 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_4 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_5 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_80_3  & 1)*-100+(#a_80_4  & 1)*-100+(#a_80_5  & 1)*-100) >=3
 
}
rule HackTool_Win32_Patcher_AMTB_2{
	meta:
		description = "HackTool:Win32/Patcher!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_80_0 = {52 4c 7a 65 72 20 50 61 74 63 68 65 72 } //RLzer Patcher  1
		$a_80_1 = {50 41 54 43 48 2e 53 45 41 52 43 48 } //PATCH.SEARCH  1
		$a_80_2 = {45 72 72 6f 72 3a 20 53 63 72 69 70 74 65 72 72 6f 72 } //Error: Scripterror  1
		$a_80_3 = {50 41 54 43 48 2e 53 54 52 } //PATCH.STR  1
		$a_80_4 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_5 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_6 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*-100+(#a_80_5  & 1)*-100+(#a_80_6  & 1)*-100) >=4
 
}
rule HackTool_Win32_Patcher_AMTB_3{
	meta:
		description = "HackTool:Win32/Patcher!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_80_0 = {54 53 52 68 20 54 65 61 4d 20 50 52 4f 55 44 4c 59 20 50 52 45 53 45 4e 54 53 20 3a } //TSRh TeaM PROUDLY PRESENTS :  1
		$a_80_1 = {54 61 68 6f 6d 61 } //Tahoma  1
		$a_80_2 = {63 68 6f 6f 73 65 20 74 61 72 67 65 74 20 66 69 6c 65 20 2e 2e 2e } //choose target file ...  1
		$a_80_3 = {43 72 61 63 6b 65 64 20 62 79 } //Cracked by  1
		$a_80_4 = {39 39 2d 39 39 2d 39 39 39 39 } //99-99-9999  1
		$a_80_5 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_6 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_7 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*-100+(#a_80_6  & 1)*-100+(#a_80_7  & 1)*-100) >=5
 
}
rule HackTool_Win32_Patcher_AMTB_4{
	meta:
		description = "HackTool:Win32/Patcher!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 00 61 00 74 00 63 00 68 00 20 00 63 00 72 00 65 00 61 00 74 00 65 00 64 00 20 00 62 00 79 00 20 00 54 00 6f 00 6c 00 61 00 27 00 73 00 20 00 50 00 61 00 74 00 63 00 68 00 69 00 6e 00 67 00 20 00 45 00 6e 00 67 00 69 00 6e 00 65 00 } //1 Patch created by Tola's Patching Engine
		$a_80_1 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_2 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_3 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
		$a_80_4 = {4d 75 6c 74 69 45 78 74 72 61 63 74 6f 72 2e 65 78 65 } //MultiExtractor.exe  -100
	condition:
		((#a_01_0  & 1)*1+(#a_80_1  & 1)*-100+(#a_80_2  & 1)*-100+(#a_80_3  & 1)*-100+(#a_80_4  & 1)*-100) >=1
 
}
rule HackTool_Win32_Patcher_AMTB_5{
	meta:
		description = "HackTool:Win32/Patcher!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {5c 70 72 6f 67 77 72 70 2e 69 6e 69 } //\progwrp.ini  2
		$a_80_1 = {50 52 4f 47 57 52 50 20 50 61 74 63 68 65 72 } //PROGWRP Patcher  2
		$a_80_2 = {63 3a 5c 55 73 65 72 73 5c 77 69 6e 33 32 5c 44 6f 63 75 6d 65 6e 74 73 5c 70 72 6f 67 77 72 70 5f 70 61 74 63 68 65 72 5c 57 69 64 65 76 69 6e 65 20 50 61 74 63 68 5c 77 69 64 65 76 69 6e 65 5f 70 61 74 63 68 2e 70 64 62 } //c:\Users\win32\Documents\progwrp_patcher\Widevine Patch\widevine_patch.pdb  2
		$a_80_3 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_4 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_5 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*-100+(#a_80_4  & 1)*-100+(#a_80_5  & 1)*-100) >=6
 
}