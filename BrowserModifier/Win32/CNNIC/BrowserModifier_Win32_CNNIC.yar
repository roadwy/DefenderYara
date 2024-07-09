
rule BrowserModifier_Win32_CNNIC{
	meta:
		description = "BrowserModifier:Win32/CNNIC,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 70 69 65 5f 53 74 61 72 74 48 6f 6f 6b } //2 spie_StartHook
		$a_01_1 = {63 64 6e 73 70 69 65 2e 64 6c 6c } //2 cdnspie.dll
		$a_01_2 = {63 64 6e 75 6e 69 6e 73 2e 65 78 65 } //2 cdnunins.exe
		$a_01_3 = {43 64 6e 48 69 64 65 } //2 CdnHide
		$a_01_4 = {5c 63 64 6e 70 72 65 76 2e 64 61 74 } //2 \cdnprev.dat
		$a_01_5 = {5c 63 64 6e 70 72 6f 74 2e 64 61 74 } //2 \cdnprot.dat
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=10
 
}
rule BrowserModifier_Win32_CNNIC_2{
	meta:
		description = "BrowserModifier:Win32/CNNIC,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 75 73 74 72 2e 64 6c 6c 00 63 6c 69 65 6e 74 00 00 00 } //2
		$a_02_1 = {68 70 12 00 00 68 38 90 90 00 10 [0-10] ff 15 04 80 00 10 [0-08] ff 15 00 80 00 10 33 c0 85 [0-08] 0f 95 c0 } //2
		$a_01_2 = {45 52 52 4f 52 3a 20 43 6f 75 6c 64 20 6e 6f 74 20 6f 70 65 6e 20 49 44 45 32 31 32 30 31 2e 56 58 44 20 66 69 6c 65 } //2 ERROR: Could not open IDE21201.VXD file
		$a_01_3 = {4e 65 74 62 69 6f 73 00 4e 45 54 41 50 49 33 32 2e 64 6c 6c 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_02_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}
rule BrowserModifier_Win32_CNNIC_3{
	meta:
		description = "BrowserModifier:Win32/CNNIC,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6c 69 65 6e 74 2e 44 4c 4c 00 63 6c 69 65 6e 74 00 00 00 } //2
		$a_02_1 = {68 70 12 00 00 68 38 90 90 00 10 [0-10] ff 15 04 80 00 10 [0-08] ff 15 00 80 00 10 33 c0 85 [0-08] 0f 95 c0 } //2
		$a_01_2 = {45 52 52 4f 52 3a 20 43 6f 75 6c 64 20 6e 6f 74 20 6f 70 65 6e 20 49 44 45 32 31 32 30 31 2e 56 58 44 20 66 69 6c 65 } //2 ERROR: Could not open IDE21201.VXD file
		$a_01_3 = {4e 65 74 62 69 6f 73 00 4e 45 54 41 50 49 33 32 2e 64 6c 6c 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_02_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}
rule BrowserModifier_Win32_CNNIC_4{
	meta:
		description = "BrowserModifier:Win32/CNNIC,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {5b 4b 44 65 6e 79 43 68 61 72 61 63 74 65 72 53 74 72 69 6e 67 5d } //1 [KDenyCharacterString]
		$a_01_1 = {5b 52 65 67 50 72 6f 74 65 63 74 44 65 6e 79 5d } //1 [RegProtectDeny]
		$a_01_2 = {5b 54 72 75 73 74 50 72 6f 63 65 73 73 4e 61 6d 65 5d } //1 [TrustProcessName]
		$a_01_3 = {63 64 6e 70 72 6f 74 2e 64 61 74 } //2 cdnprot.dat
		$a_01_4 = {5b 44 65 6e 79 50 72 6f 63 65 73 73 4e 61 6d 65 5d } //1 [DenyProcessName]
		$a_01_5 = {39 41 35 37 38 43 39 38 2d 33 43 32 46 2d 34 36 33 30 2d 38 39 30 42 2d 46 43 30 34 31 39 36 45 46 34 32 30 } //2 9A578C98-3C2F-4630-890B-FC04196EF420
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2) >=5
 
}
rule BrowserModifier_Win32_CNNIC_5{
	meta:
		description = "BrowserModifier:Win32/CNNIC,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 43 4e 4e 49 43 5c 43 64 6e 43 6c 69 65 6e 74 5c 43 6f 6d 6d 6f 6e } //2 SOFTWARE\CNNIC\CdnClient\Common
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 43 4e 4e 49 43 5c 43 64 6e 43 6c 69 65 6e 74 5c 49 6e 73 74 61 6c 6c 49 6e 66 6f } //2 SOFTWARE\CNNIC\CdnClient\InstallInfo
		$a_01_2 = {25 73 5c 75 70 64 61 74 65 5c 25 73 } //3 %s\update\%s
		$a_01_3 = {63 64 6e 76 65 72 73 2e 64 61 74 } //3 cdnvers.dat
		$a_01_4 = {52 65 6c 61 79 55 70 64 61 74 65 } //2 RelayUpdate
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 43 4e 4e 49 43 5c 43 64 6e 43 6c 69 65 6e 74 5c 55 70 64 61 74 65 } //2 SOFTWARE\CNNIC\CdnClient\Update
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}
rule BrowserModifier_Win32_CNNIC_6{
	meta:
		description = "BrowserModifier:Win32/CNNIC,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 43 4e 4e 49 43 5c 43 64 6e 43 6c 69 65 6e 74 5c 52 75 6e 41 63 74 } //3 SOFTWARE\CNNIC\CdnClient\RunAct
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 43 4e 4e 49 43 5c 43 64 6e 43 6c 69 65 6e 74 5c 55 70 64 61 74 65 } //3 SOFTWARE\CNNIC\CdnClient\Update
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 4f 70 74 69 6f 6e 73 5c 43 44 4e 43 4c 49 45 4e 54 5c } //3 SOFTWARE\Microsoft\Internet Explorer\AdvancedOptions\CDNCLIENT\
		$a_01_3 = {2f 63 64 6e 43 6c 69 65 6e 74 2f 75 70 64 61 74 65 } //3 /cdnClient/update
		$a_01_4 = {63 64 6e 75 6e 69 6e 73 2e 65 78 65 } //2 cdnunins.exe
		$a_01_5 = {55 70 64 61 74 65 20 63 6f 6d 70 6c 65 74 65 64 2e } //1 Update completed.
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1) >=12
 
}
rule BrowserModifier_Win32_CNNIC_7{
	meta:
		description = "BrowserModifier:Win32/CNNIC,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_01_0 = {55 6e 69 6e 73 74 61 6c 6c 20 63 2d 4e 61 76 2e 6c 6e 6b } //2 Uninstall c-Nav.lnk
		$a_01_1 = {41 62 6f 75 74 20 63 2d 4e 61 76 2e 75 72 6c } //2 About c-Nav.url
		$a_01_2 = {63 64 6e 61 75 78 2e 64 6c 6c } //3 cdnaux.dll
		$a_01_3 = {4d 61 6e 61 67 65 72 53 68 6f 72 74 43 75 74 } //1 ManagerShortCut
		$a_01_4 = {3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 4e 4e 49 43 5c 43 64 6e 5c } //2 :\Program Files\CNNIC\Cdn\
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 43 64 6e 43 6c 69 65 6e 74 } //2 Software\Microsoft\Windows\CurrentVersion\Uninstall\CdnClient
		$a_01_6 = {53 4f 46 54 57 41 52 45 5c 43 4e 4e 49 43 5c 43 64 6e 43 6c 69 65 6e 74 5c 43 6f 6d 6d 6f 6e } //2 SOFTWARE\CNNIC\CdnClient\Common
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=10
 
}
rule BrowserModifier_Win32_CNNIC_8{
	meta:
		description = "BrowserModifier:Win32/CNNIC,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_01_0 = {63 64 6e 75 70 } //1 cdnup
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 43 4e 4e 49 43 5c 43 64 6e 43 6c 69 65 6e 74 5c 44 69 73 70 6c 61 79 5c 54 79 70 65 64 56 4b 57 73 } //2 Software\CNNIC\CdnClient\Display\TypedVKWs
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 4f 70 74 69 6f 6e 73 5c 43 44 4e 43 4c 49 45 4e 54 } //2 SOFTWARE\Microsoft\Internet Explorer\AdvancedOptions\CDNCLIENT
		$a_01_3 = {43 68 69 6e 65 73 65 20 4e 61 76 69 67 61 74 69 6f 6e } //2 Chinese Navigation
		$a_01_4 = {63 64 6e 70 72 68 2e 64 6c 6c } //2 cdnprh.dll
		$a_01_5 = {70 72 68 5f 53 65 74 46 69 6c 74 65 72 } //2 prh_SetFilter
		$a_01_6 = {45 6e 61 62 6c 65 20 43 68 69 6e 65 73 65 20 44 6f 6d 61 69 6e 20 4e 61 6d 65 20 4d 61 69 6c 69 6e 67 20 53 79 73 74 65 6d } //2 Enable Chinese Domain Name Mailing System
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=10
 
}
rule BrowserModifier_Win32_CNNIC_9{
	meta:
		description = "BrowserModifier:Win32/CNNIC,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 08 00 00 "
		
	strings :
		$a_01_0 = {43 68 69 6e 65 73 65 20 4e 61 76 69 67 61 74 69 6f 6e 20 55 70 67 72 61 64 65 } //3 Chinese Navigation Upgrade
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 43 4e 4e 49 43 5c 43 64 6e 43 6c 69 65 6e 74 5c 55 70 64 61 74 65 } //3 SOFTWARE\CNNIC\CdnClient\Update
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 4f 70 74 69 6f 6e 73 5c 43 44 4e 43 4c 49 45 4e 54 5c 55 50 44 41 54 45 5c 50 4f 50 55 50 } //3 SOFTWARE\Microsoft\Internet Explorer\AdvancedOptions\CDNCLIENT\UPDATE\POPUP
		$a_01_3 = {43 4e 4e 49 43 20 4e 65 77 73 20 57 69 6e 64 6f 77 } //3 CNNIC News Window
		$a_01_4 = {45 6e 61 62 6c 65 54 61 73 6b 50 6f 70 75 70 } //2 EnableTaskPopup
		$a_01_5 = {63 64 6e 5f 6d 75 74 65 78 5f 63 64 6e 75 70 77 69 6e } //5 cdn_mutex_cdnupwin
		$a_01_6 = {63 64 6e 75 70 6c 69 62 2e 64 6c 6c } //3 cdnuplib.dll
		$a_01_7 = {52 65 6c 61 79 55 70 64 61 74 65 } //2 RelayUpdate
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2+(#a_01_5  & 1)*5+(#a_01_6  & 1)*3+(#a_01_7  & 1)*2) >=17
 
}
rule BrowserModifier_Win32_CNNIC_10{
	meta:
		description = "BrowserModifier:Win32/CNNIC,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 "
		
	strings :
		$a_01_0 = {63 64 6e 70 72 68 2e 64 6c 6c } //3 cdnprh.dll
		$a_01_1 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 43 64 6e 70 72 6f 74 } //3 SYSTEM\CurrentControlSet\Services\Cdnprot
		$a_01_2 = {5c 5c 2e 5c 43 44 4e 50 52 4f 54 } //4 \\.\CDNPROT
		$a_01_3 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 42 72 6f 77 73 65 72 5c 53 65 63 75 72 69 74 79 } //1 SYSTEM\CurrentControlSet\Services\Browser\Security
		$a_01_4 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 56 78 44 5c 43 64 6e 70 72 6f 74 } //3 System\CurrentControlSet\Services\VxD\Cdnprot
		$a_01_5 = {63 64 6e 70 72 6f 74 2e 76 78 64 } //3 cdnprot.vxd
		$a_01_6 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 43 6e 73 4d 69 6e 4b 50 } //3 System\CurrentControlSet\Services\CnsMinKP
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*4+(#a_01_3  & 1)*1+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3+(#a_01_6  & 1)*3) >=15
 
}
rule BrowserModifier_Win32_CNNIC_11{
	meta:
		description = "BrowserModifier:Win32/CNNIC,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0b 00 00 "
		
	strings :
		$a_01_0 = {69 64 6e 63 6f 6e 76 2e 64 6c 6c } //1 idnconv.dll
		$a_01_1 = {69 64 6e 63 6f 6e 76 73 2e 64 6c 6c } //1 idnconvs.dll
		$a_01_2 = {43 6e 73 4d 69 6e } //2 CnsMin
		$a_01_3 = {52 65 64 42 75 72 67 65 65 } //2 RedBurgee
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 43 4e 4e 49 43 5c 43 64 6e 43 6c 69 65 6e 74 5c 43 6f 6e 73 6f 6c 65 } //2 SOFTWARE\CNNIC\CdnClient\Console
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 43 4e 4e 49 43 5c 43 64 6e 43 6c 69 65 6e 74 5c 49 6e 73 74 61 6c 6c 49 6e 66 6f } //2 SOFTWARE\CNNIC\CdnClient\InstallInfo
		$a_01_6 = {69 64 6e 5f 66 72 65 65 } //1 idn_free
		$a_01_7 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 4f 70 74 69 6f 6e 73 5c 43 44 4e 43 4c 49 45 4e 54 5c 49 44 4e 4b 57 5c } //2 SOFTWARE\Microsoft\Internet Explorer\AdvancedOptions\CDNCLIENT\IDNKW\
		$a_01_8 = {45 6e 61 62 6c 65 4b 77 } //2 EnableKw
		$a_01_9 = {45 6e 61 62 6c 65 49 64 6e } //2 EnableIdn
		$a_01_10 = {63 64 6e 64 65 74 2e 64 6c 6c } //1 cdndet.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*1) >=10
 
}
rule BrowserModifier_Win32_CNNIC_12{
	meta:
		description = "BrowserModifier:Win32/CNNIC,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 64 6e 53 69 67 6e 2e 64 6c 6c } //4 CdnSign.dll
		$a_01_1 = {43 73 6e 5f 53 70 6c 69 74 53 67 6e 46 69 6c 65 } //1 Csn_SplitSgnFile
		$a_01_2 = {43 73 6e 5f 56 65 72 69 66 79 53 67 6e 46 69 6c 65 } //1 Csn_VerifySgnFile
		$a_01_3 = {43 41 35 46 31 33 36 41 36 37 43 36 42 35 30 41 42 42 30 42 45 38 46 41 43 39 41 32 42 34 42 33 43 34 46 31 35 37 33 31 41 35 45 36 33 45 34 32 43 41 44 33 31 39 33 43 37 46 41 45 30 45 31 36 37 31 33 33 44 32 42 39 45 31 37 34 45 35 41 39 30 44 37 44 41 32 44 43 34 46 41 35 42 32 46 36 38 39 32 31 41 43 35 37 32 35 32 36 31 43 32 46 34 35 44 39 43 32 35 41 36 33 32 30 34 46 42 43 33 36 33 31 37 39 38 39 38 34 41 33 34 30 33 44 36 42 36 34 41 35 34 41 36 36 31 37 41 44 37 35 33 45 45 35 37 33 41 46 45 45 42 31 30 38 41 37 32 46 33 34 30 35 34 36 46 33 32 42 46 34 31 34 36 39 46 45 39 44 44 31 30 43 38 37 44 43 35 44 44 30 46 36 35 46 41 44 39 35 31 38 32 41 30 31 45 41 41 38 42 35 36 33 35 38 38 45 44 37 38 31 37 36 33 36 32 45 44 30 31 34 43 42 31 38 } //2 CA5F136A67C6B50ABB0BE8FAC9A2B4B3C4F15731A5E63E42CAD3193C7FAE0E167133D2B9E174E5A90D7DA2DC4FA5B2F68921AC5725261C2F45D9C25A63204FBC3631798984A3403D6B64A54A6617AD753EE573AFEEB108A72F340546F32BF41469FE9DD10C87DC5DD0F65FAD95182A01EAA8B563588ED78176362ED014CB18
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=7
 
}
rule BrowserModifier_Win32_CNNIC_13{
	meta:
		description = "BrowserModifier:Win32/CNNIC,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0b 00 00 "
		
	strings :
		$a_01_0 = {63 64 6e 70 72 68 2e 64 6c 6c } //1 cdnprh.dll
		$a_01_1 = {63 64 6e 70 72 6f 74 2e 73 79 73 } //1 cdnprot.sys
		$a_01_2 = {63 64 6e 75 6e 69 6e 73 2e 65 78 65 } //1 cdnunins.exe
		$a_01_3 = {63 64 6e 75 70 2e 65 78 65 } //1 cdnup.exe
		$a_01_4 = {63 64 6e 76 65 72 73 2e 64 61 74 } //1 cdnvers.dat
		$a_01_5 = {69 64 6e 63 6f 6e 76 73 2e 64 6c 6c } //1 idnconvs.dll
		$a_01_6 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 63 64 6e 70 72 6f 74 } //2 SYSTEM\CurrentControlSet\Services\cdnprot
		$a_01_7 = {53 4f 46 54 57 41 52 45 5c 43 4e 4e 49 43 5c 43 64 6e 43 6c 69 65 6e 74 5c 43 6f 6d 6d 6f 6e } //2 SOFTWARE\CNNIC\CdnClient\Common
		$a_01_8 = {49 6e 73 74 61 6c 6c 20 77 69 6c 6c 20 63 6f 6e 74 69 6e 75 65 20 61 66 74 65 72 20 72 65 73 74 61 72 74 69 6e 67 20 63 6f 6d 70 75 74 65 72 21 } //2 Install will continue after restarting computer!
		$a_01_9 = {44 6f 20 79 6f 75 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //2 Do you reboot now?
		$a_01_10 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6d 61 67 65 20 46 69 6c 65 20 45 78 65 63 75 74 69 6f 6e 20 4f 70 74 69 6f 6e 73 5c 63 64 6e } //4 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cdn
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*4) >=12
 
}
rule BrowserModifier_Win32_CNNIC_14{
	meta:
		description = "BrowserModifier:Win32/CNNIC,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 09 00 00 "
		
	strings :
		$a_01_0 = {70 72 68 5f 55 6e 49 6e 73 74 61 6c 6c 44 72 69 76 65 72 } //3 prh_UnInstallDriver
		$a_01_1 = {63 64 6e 70 72 6f 74 2e 64 61 74 } //3 cdnprot.dat
		$a_01_2 = {63 64 6e 75 70 2e 65 78 65 } //3 cdnup.exe
		$a_01_3 = {63 64 6e 76 65 72 73 2e 64 61 74 } //3 cdnvers.dat
		$a_01_4 = {43 64 6e 43 74 72 } //3 CdnCtr
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 43 6f 64 65 20 53 74 6f 72 65 20 44 61 74 61 62 61 73 65 5c 44 69 73 74 72 69 62 75 74 69 6f 6e 20 55 6e 69 74 73 5c 7b 39 41 35 37 38 43 39 38 2d 33 43 32 46 2d 34 36 33 30 2d 38 39 30 42 2d 46 43 30 34 31 39 36 45 46 34 32 30 7d } //3 SOFTWARE\Microsoft\Code Store Database\Distribution Units\{9A578C98-3C2F-4630-890B-FC04196EF420}
		$a_01_6 = {68 74 74 70 3a 2f 2f 6e 61 6d 65 2e 63 6e 6e 69 63 2e 63 6e 2f 63 6e 2e 64 6c 6c } //3 http://name.cnnic.cn/cn.dll
		$a_01_7 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 43 64 6e 43 6c 69 65 6e 74 } //3 Software\Microsoft\Windows\CurrentVersion\Uninstall\CdnClient
		$a_01_8 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 4f 70 74 69 6f 6e 73 5c 43 44 4e 43 4c 49 45 4e 54 } //3 SOFTWARE\Microsoft\Internet Explorer\AdvancedOptions\CDNCLIENT
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3+(#a_01_6  & 1)*3+(#a_01_7  & 1)*3+(#a_01_8  & 1)*3) >=21
 
}
rule BrowserModifier_Win32_CNNIC_15{
	meta:
		description = "BrowserModifier:Win32/CNNIC,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0b 00 00 "
		
	strings :
		$a_01_0 = {43 73 6e 5f 53 70 6c 69 74 53 67 6e 46 69 6c 65 } //1 Csn_SplitSgnFile
		$a_01_1 = {43 73 6e 5f 56 65 72 69 66 79 53 67 6e 46 69 6c 65 } //1 Csn_VerifySgnFile
		$a_01_2 = {63 6e 70 72 6f 76 2e 64 61 74 } //1 cnprov.dat
		$a_01_3 = {61 64 70 72 6f 74 2e 73 79 73 } //1 adprot.sys
		$a_01_4 = {5c 63 64 6e 70 72 6f 74 5c 64 72 69 76 65 72 5c 6f 62 6a 66 72 65 5c 69 33 38 36 5c 63 6e 70 72 6f 76 2e 70 64 62 } //4 \cdnprot\driver\objfre\i386\cnprov.pdb
		$a_01_5 = {68 74 74 70 3a 2f 2f 6e 61 6d 65 2e 63 6e 6e 69 63 2e 63 6e 2f 63 6e 2e 64 6c 6c 3f 70 69 64 3d } //4 http://name.cnnic.cn/cn.dll?pid=
		$a_01_6 = {63 64 6e 68 69 6e 74 } //1 cdnhint
		$a_01_7 = {63 64 6e 70 6f 70 75 70 } //1 cdnpopup
		$a_01_8 = {43 68 69 6e 65 73 65 20 44 6f 6d 61 69 6e 20 4e 61 6d 65 20 63 6c 69 65 6e 74 2d 65 6e 64 20 73 6f 66 74 77 61 72 65 20 68 61 73 20 62 65 65 6e 20 64 65 74 65 63 74 65 64 2c 20 77 6f 75 6c 64 20 79 6f 75 20 6c 69 6b 65 20 74 6f 20 } //4 Chinese Domain Name client-end software has been detected, would you like to 
		$a_01_9 = {3c 66 6f 72 6d 20 6e 61 6d 65 3d 22 66 22 20 61 63 74 69 6f 6e 3d 22 68 74 74 70 3a 2f 2f 6e 61 6d 65 2e 63 6e 6e 69 63 2e 63 6e 2f 63 6e 2e 64 6c 6c 22 3e } //4 <form name="f" action="http://name.cnnic.cn/cn.dll">
		$a_01_10 = {77 69 6e 64 6f 77 2e 6f 70 65 6e 28 22 68 74 74 70 3a 2f 2f 6e 61 6d 65 2e 63 6e 6e 69 63 2e 63 6e 2f 63 6e 2e 64 6c 6c 3f 63 68 61 72 73 65 74 3d 75 74 66 2d 38 26 6e 61 6d 65 3d 22 2b 71 65 29 3b } //4 window.open("http://name.cnnic.cn/cn.dll?charset=utf-8&name="+qe);
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*4+(#a_01_5  & 1)*4+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*4+(#a_01_9  & 1)*4+(#a_01_10  & 1)*4) >=10
 
}
rule BrowserModifier_Win32_CNNIC_16{
	meta:
		description = "BrowserModifier:Win32/CNNIC,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 09 00 00 "
		
	strings :
		$a_01_0 = {5b 52 65 67 50 72 6f 74 65 63 74 44 65 6e 79 5d } //1 [RegProtectDeny]
		$a_01_1 = {5b 54 72 75 73 74 50 72 6f 63 65 73 73 4e 61 6d 65 5d } //1 [TrustProcessName]
		$a_01_2 = {63 6e 70 72 6f 76 2e 64 61 74 } //1 cnprov.dat
		$a_01_3 = {43 44 4e 55 4e 49 4e 53 2e 45 58 45 } //1 CDNUNINS.EXE
		$a_01_4 = {43 44 4e 55 50 2e 45 58 45 } //1 CDNUP.EXE
		$a_01_5 = {5c 63 64 6e 70 72 6f 74 5c 64 72 69 76 65 72 5c 6f 62 6a 66 72 65 5c 69 33 38 36 5c 63 6e 70 72 6f 76 2e 70 64 62 } //4 \cdnprot\driver\objfre\i386\cnprov.pdb
		$a_01_6 = {5c 00 52 00 45 00 47 00 49 00 53 00 54 00 52 00 59 00 5c 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 63 00 6e 00 70 00 72 00 6f 00 76 00 } //3 \REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\cnprov
		$a_01_7 = {41 00 44 00 50 00 52 00 4f 00 54 00 2e 00 53 00 59 00 53 00 } //2 ADPROT.SYS
		$a_01_8 = {5c 00 42 00 61 00 73 00 65 00 4e 00 61 00 6d 00 65 00 64 00 4f 00 62 00 6a 00 65 00 63 00 74 00 73 00 5c 00 37 00 45 00 41 00 34 00 44 00 30 00 37 00 32 00 2d 00 33 00 42 00 46 00 37 00 2d 00 34 00 61 00 63 00 66 00 2d 00 42 00 44 00 32 00 31 00 2d 00 46 00 41 00 46 00 32 00 31 00 45 00 46 00 31 00 31 00 30 00 39 00 30 00 } //3 \BaseNamedObjects\7EA4D072-3BF7-4acf-BD21-FAF21EF11090
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*4+(#a_01_6  & 1)*3+(#a_01_7  & 1)*2+(#a_01_8  & 1)*3) >=10
 
}
rule BrowserModifier_Win32_CNNIC_17{
	meta:
		description = "BrowserModifier:Win32/CNNIC,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {49 50 2d 43 4e 4e 49 43 } //4 IP-CNNIC
		$a_00_1 = {5c 00 52 00 45 00 47 00 49 00 53 00 54 00 52 00 59 00 5c 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 54 00 63 00 70 00 69 00 70 00 5c 00 50 00 61 00 72 00 61 00 6d 00 65 00 74 00 65 00 72 00 73 00 5c 00 49 00 6e 00 74 00 65 00 72 00 66 00 61 00 63 00 65 00 73 00 } //1 \REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces
		$a_00_2 = {5c 00 52 00 45 00 47 00 49 00 53 00 54 00 52 00 59 00 5c 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 43 00 4e 00 4e 00 49 00 43 00 5c 00 43 00 64 00 6e 00 43 00 6c 00 69 00 65 00 6e 00 74 00 5c 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 49 00 6e 00 66 00 6f 00 } //2 \REGISTRY\MACHINE\SOFTWARE\CNNIC\CdnClient\InstallInfo
		$a_00_3 = {5c 00 63 00 64 00 6e 00 74 00 72 00 61 00 6e 00 2e 00 64 00 61 00 74 00 } //2 \cdntran.dat
		$a_00_4 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 43 00 44 00 4e 00 54 00 52 00 41 00 4e 00 } //3 \Device\CDNTRAN
		$a_00_5 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 43 00 44 00 4e 00 54 00 52 00 41 00 4e 00 } //3 \DosDevices\CDNTRAN
	condition:
		((#a_01_0  & 1)*4+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*3+(#a_00_5  & 1)*3) >=9
 
}
rule BrowserModifier_Win32_CNNIC_18{
	meta:
		description = "BrowserModifier:Win32/CNNIC,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 0e 00 00 "
		
	strings :
		$a_01_0 = {69 6e 73 74 61 6c 6c 2e 65 78 65 } //1 install.exe
		$a_01_1 = {73 65 74 75 70 2e 65 78 65 } //1 setup.exe
		$a_01_2 = {7b 37 43 41 38 33 43 46 31 2d 33 41 45 41 2d 34 32 44 30 2d 41 34 45 33 2d 31 35 39 34 46 43 36 45 34 38 42 32 7d } //1 {7CA83CF1-3AEA-42D0-A4E3-1594FC6E48B2}
		$a_01_3 = {7b 31 42 30 45 37 37 31 36 2d 38 39 38 45 2d 34 38 43 43 2d 39 36 39 30 2d 34 45 33 33 38 45 38 44 45 31 44 33 7d } //1 {1B0E7716-898E-48CC-9690-4E338E8DE1D3}
		$a_01_4 = {7b 41 42 45 43 36 31 30 33 2d 46 36 41 43 2d 34 33 41 33 2d 38 33 34 46 2d 46 42 30 33 46 42 41 33 33 39 41 32 7d } //1 {ABEC6103-F6AC-43A3-834F-FB03FBA339A2}
		$a_01_5 = {7b 42 42 39 33 36 33 32 33 2d 31 39 46 41 2d 34 35 32 31 2d 42 41 32 39 2d 45 43 41 36 41 31 32 31 42 43 37 38 7d } //1 {BB936323-19FA-4521-BA29-ECA6A121BC78}
		$a_01_6 = {7b 44 31 35 37 33 33 30 41 2d 39 45 46 33 2d 34 39 46 38 2d 39 41 36 37 2d 34 31 34 31 41 43 34 31 41 44 44 34 7d } //1 {D157330A-9EF3-49F8-9A67-4141AC41ADD4}
		$a_01_7 = {7b 42 38 33 46 43 32 37 33 2d 33 35 32 32 2d 34 43 43 36 2d 39 32 45 43 2d 37 35 43 43 38 36 36 37 38 44 41 34 7d } //1 {B83FC273-3522-4CC6-92EC-75CC86678DA4}
		$a_01_8 = {5c 64 72 69 76 65 72 73 5c 77 69 6e 63 6c 2e 73 79 73 } //5 \drivers\wincl.sys
		$a_01_9 = {5c 5c 2e 5c 43 4e 53 4d 49 4e 4b 50 2e 56 58 44 } //8 \\.\CNSMINKP.VXD
		$a_01_10 = {5c 5c 2e 5c 57 49 4e 43 4c 2e 56 58 44 } //5 \\.\WINCL.VXD
		$a_01_11 = {5c 77 69 6e 63 6c 2e 76 78 64 } //5 \wincl.vxd
		$a_01_12 = {49 6e 73 74 61 6c 6c 20 77 69 6c 6c 20 63 6f 6e 74 69 6e 75 65 20 61 66 74 65 72 20 72 65 73 74 61 72 74 69 6e 67 20 63 6f 6d 70 75 74 65 72 21 } //4 Install will continue after restarting computer!
		$a_01_13 = {44 6f 20 79 6f 75 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //4 Do you reboot now?
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*5+(#a_01_9  & 1)*8+(#a_01_10  & 1)*5+(#a_01_11  & 1)*5+(#a_01_12  & 1)*4+(#a_01_13  & 1)*4) >=20
 
}
rule BrowserModifier_Win32_CNNIC_19{
	meta:
		description = "BrowserModifier:Win32/CNNIC,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 0e 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 43 4e 4e 49 43 5c 43 64 6e 43 6c 69 65 6e 74 5c 55 70 64 61 74 65 } //3 SOFTWARE\CNNIC\CdnClient\Update
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c 7b 44 31 35 37 33 33 30 41 2d 39 45 46 33 2d 34 39 46 38 2d 39 41 36 37 2d 34 31 34 31 41 43 34 31 41 44 44 34 7d } //3 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{D157330A-9EF3-49F8-9A67-4141AC41ADD4}
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 43 4e 4e 49 43 5c 43 64 6e 43 6c 69 65 6e 74 5c 52 75 6e 41 63 74 } //3 SOFTWARE\CNNIC\CdnClient\RunAct
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 43 4e 4e 49 43 5c 43 64 6e 43 6c 69 65 6e 74 5c 49 6e 73 74 61 6c 6c 49 6e 66 6f } //3 SOFTWARE\CNNIC\CdnClient\InstallInfo
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 4f 70 74 69 6f 6e 73 5c 43 44 4e 43 4c 49 45 4e 54 5c } //3 SOFTWARE\Microsoft\Internet Explorer\AdvancedOptions\CDNCLIENT\
		$a_01_5 = {43 68 69 6e 65 73 65 20 4e 61 76 69 67 61 74 69 6f 6e } //3 Chinese Navigation
		$a_01_6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 45 78 74 65 6e 73 69 6f 6e 73 5c 7b 35 43 33 38 35 33 43 46 2d 43 37 45 30 2d 34 39 34 36 2d 42 33 46 41 2d 31 41 42 44 42 36 46 34 38 31 30 38 7d } //3 SOFTWARE\Microsoft\Internet Explorer\Extensions\{5C3853CF-C7E0-4946-B3FA-1ABDB6F48108}
		$a_00_7 = {41 00 75 00 74 00 6f 00 2d 00 53 00 75 00 67 00 67 00 65 00 73 00 74 00 20 00 44 00 72 00 6f 00 70 00 64 00 6f 00 77 00 6e 00 } //2 Auto-Suggest Dropdown
		$a_01_8 = {53 6f 66 74 77 61 72 65 5c 43 4e 4e 49 43 5c 43 64 6e 43 6c 69 65 6e 74 5c 44 69 73 70 6c 61 79 5c 54 79 70 65 64 53 4b 57 73 } //3 Software\CNNIC\CdnClient\Display\TypedSKWs
		$a_01_9 = {53 6f 66 74 77 61 72 65 5c 43 4e 4e 49 43 5c 43 64 6e 43 6c 69 65 6e 74 5c 44 69 73 70 6c 61 79 5c 54 79 70 65 64 56 4b 57 73 } //3 Software\CNNIC\CdnClient\Display\TypedVKWs
		$a_00_10 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 43 00 4e 00 4e 00 49 00 43 00 5c 00 43 00 64 00 6e 00 43 00 6c 00 69 00 65 00 6e 00 74 00 5c 00 44 00 69 00 73 00 70 00 6c 00 61 00 79 00 5c 00 54 00 79 00 70 00 65 00 64 00 53 00 4b 00 57 00 73 00 } //3 Software\CNNIC\CdnClient\Display\TypedSKWs
		$a_00_11 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 43 00 4e 00 4e 00 49 00 43 00 5c 00 43 00 64 00 6e 00 43 00 6c 00 69 00 65 00 6e 00 74 00 5c 00 44 00 69 00 73 00 70 00 6c 00 61 00 79 00 5c 00 54 00 79 00 70 00 65 00 64 00 56 00 4b 00 57 00 73 00 } //3 Software\CNNIC\CdnClient\Display\TypedVKWs
		$a_01_12 = {68 74 74 70 3a 2f 2f 6e 61 6d 65 2e 63 6e 6e 69 63 2e } //2 http://name.cnnic.
		$a_00_13 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6e 00 61 00 6d 00 65 00 2e 00 63 00 6e 00 6e 00 69 00 63 00 2e 00 } //2 http://name.cnnic.
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3+(#a_01_6  & 1)*3+(#a_00_7  & 1)*2+(#a_01_8  & 1)*3+(#a_01_9  & 1)*3+(#a_00_10  & 1)*3+(#a_00_11  & 1)*3+(#a_01_12  & 1)*2+(#a_00_13  & 1)*2) >=18
 
}
rule BrowserModifier_Win32_CNNIC_20{
	meta:
		description = "BrowserModifier:Win32/CNNIC,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 0a 00 00 "
		
	strings :
		$a_01_0 = {5c 00 52 00 45 00 47 00 49 00 53 00 54 00 52 00 59 00 5c 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 43 00 4e 00 4e 00 49 00 43 00 5c 00 43 00 64 00 6e 00 43 00 6c 00 69 00 65 00 6e 00 74 00 5c 00 52 00 75 00 6e 00 41 00 63 00 74 00 } //3 \REGISTRY\MACHINE\SOFTWARE\CNNIC\CdnClient\RunAct
		$a_01_1 = {5c 00 52 00 45 00 47 00 49 00 53 00 54 00 52 00 59 00 5c 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 43 00 64 00 6e 00 50 00 72 00 6f 00 74 00 } //3 \REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\CdnProt
		$a_01_2 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 43 00 64 00 6e 00 50 00 72 00 } //2 \Device\CdnPr
		$a_01_3 = {5c 00 43 00 4e 00 4e 00 49 00 43 00 5c 00 43 00 64 00 6e 00 43 00 6c 00 69 00 65 00 6e 00 74 00 5c 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 49 00 6e 00 66 00 6f 00 } //4 \CNNIC\CdnClient\InstallInfo
		$a_01_4 = {43 00 4e 00 4e 00 49 00 43 00 20 00 63 00 64 00 6e 00 70 00 72 00 6f 00 74 00 } //4 CNNIC cdnprot
		$a_01_5 = {63 00 64 00 6e 00 70 00 72 00 6f 00 74 00 2e 00 73 00 79 00 73 00 } //2 cdnprot.sys
		$a_01_6 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 43 00 64 00 6e 00 50 00 72 00 6f 00 74 00 } //3 \DosDevices\CdnProt
		$a_01_7 = {49 00 45 00 20 00 55 00 52 00 4c 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 } //1 IE URL Service
		$a_01_8 = {53 00 6d 00 61 00 72 00 74 00 20 00 43 00 61 00 72 00 64 00 20 00 45 00 76 00 65 00 6e 00 74 00 } //1 Smart Card Event
		$a_01_9 = {43 00 6e 00 73 00 4d 00 69 00 6e 00 4b 00 50 00 } //2 CnsMinKP
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*4+(#a_01_4  & 1)*4+(#a_01_5  & 1)*2+(#a_01_6  & 1)*3+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*2) >=13
 
}