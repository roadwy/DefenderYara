
rule BrowserModifier_Win32_KlipPalCby{
	meta:
		description = "BrowserModifier:Win32/KlipPalCby,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 00 70 00 64 00 61 00 74 00 65 00 72 00 5f 00 4f 00 66 00 53 00 76 00 63 00 5f 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5f 00 32 00 } //1 Updater_OfSvc_BrowserSettings_2
		$a_03_1 = {4f 00 46 00 53 00 5f 00 ?? ?? 67 00 73 00 69 00 3f 00 63 00 69 00 64 00 3d 00 7b 00 30 00 7d 00 26 00 69 00 73 00 3d 00 7b 00 31 00 7d 00 } //1
		$a_03_2 = {6b 00 6d 00 73 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 ?? ?? 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 41 00 72 00 67 00 75 00 6d 00 65 00 6e 00 74 00 73 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule BrowserModifier_Win32_KlipPalCby_2{
	meta:
		description = "BrowserModifier:Win32/KlipPalCby,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 45 20 31 31 20 66 69 78 20 2d 20 53 74 61 72 74 69 6e 67 20 66 69 78 20 26 20 4f 70 74 69 6d 69 7a 65 45 6e 61 62 6c 65 50 6c 75 67 69 6e 20 69 73 20 74 72 75 65 } //10 IE 11 fix - Starting fix & OptimizeEnablePlugin is true
		$a_01_1 = {57 72 6f 74 65 20 49 45 20 41 75 74 6f 20 45 6e 61 62 6c 65 20 49 67 6e 6f 72 65 46 72 61 6d 65 41 70 70 72 6f 76 61 6c 43 68 65 63 6b } //10 Wrote IE Auto Enable IgnoreFrameApprovalCheck
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 74 } //1 Software\Microsoft\Windows\CurrentVersion\Policies\Ext
		$a_01_3 = {49 67 6e 6f 72 65 46 72 61 6d 65 41 70 70 72 6f 76 61 6c 43 68 65 63 6b } //1 IgnoreFrameApprovalCheck
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 41 70 70 72 6f 76 65 64 45 78 74 65 6e 73 69 6f 6e 73 4d 69 67 72 61 74 69 6f 6e } //1 Software\Microsoft\Internet Explorer\ApprovedExtensionsMigration
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=12
 
}