
rule BrowserModifier_Win32_Xider{
	meta:
		description = "BrowserModifier:Win32/Xider,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 74 5c 43 4c 53 49 44 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Ext\CLSID
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 41 70 70 72 6f 76 65 64 45 78 74 65 6e 73 69 6f 6e 73 4d 69 67 72 61 74 69 6f 6e } //1 Software\Microsoft\Internet Explorer\ApprovedExtensionsMigration
		$a_01_2 = {63 72 69 65 65 6e 61 62 6c 65 72 } //2 crieenabler
		$a_01_3 = {49 65 45 6e 61 62 6c 65 72 2e 65 78 65 } //2 IeEnabler.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=6
 
}
rule BrowserModifier_Win32_Xider_2{
	meta:
		description = "BrowserModifier:Win32/Xider,SIGNATURE_TYPE_PEHSTR_EXT,22 00 22 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 74 5c 43 4c 53 49 44 } //10 SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Ext\CLSID
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 41 70 70 72 6f 76 65 64 20 45 78 74 65 6e 73 69 6f 6e 73 } //10 Software\Microsoft\Internet Explorer\Approved Extensions
		$a_01_2 = {00 65 6e 61 62 6c 65 5f 62 68 6f 00 } //10 攀慮汢彥桢o
		$a_01_3 = {63 72 69 65 65 6e 61 62 6c 65 72 } //2 crieenabler
		$a_01_4 = {49 45 45 78 74 65 6e 73 69 6f 6e 55 74 69 6c 73 } //2 IEExtensionUtils
		$a_01_5 = {49 65 45 6e 61 62 6c 65 72 2e 65 78 65 } //2 IeEnabler.exe
		$a_01_6 = {41 6c 72 65 61 64 79 20 61 70 70 72 6f 76 65 64 20 74 68 69 73 20 62 68 6f 20 69 6e 20 74 68 65 20 70 61 73 74 } //2 Already approved this bho in the past
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=34
 
}
rule BrowserModifier_Win32_Xider_3{
	meta:
		description = "BrowserModifier:Win32/Xider,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 74 5c 50 72 65 41 70 70 72 6f 76 65 64 } //10 Software\Microsoft\Windows\CurrentVersion\Ext\PreApproved
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 74 5c 43 4c 53 49 44 } //10 Software\Microsoft\Windows\CurrentVersion\Policies\Ext\CLSID
		$a_03_2 = {65 72 72 5f 75 6e 6d 69 78 69 6e 67 5f 69 65 5f 65 6e 61 62 6c 65 72 5f [0-09] 43 6f 70 79 69 6e 67 20 66 72 6f 6d [0-09] 5c [0-0f] 2e 74 6d 70 } //1
		$a_03_3 = {65 72 72 5f 65 78 74 72 61 74 69 6e 67 5f 69 65 5f 65 6e 61 62 6c 65 72 90 0a a0 00 5c [0-08] 2d [0-04] 2d [0-04] 2d [0-04] 2d [0-0c] 2d 32 2e 65 78 65 } //1
		$a_03_4 = {2f 6d 6f 6e 65 74 69 7a 61 74 69 6f 6e 2e 67 69 66 3f 65 76 65 6e 74 3d [0-02] 26 69 62 69 63 3d ?? ?? ?? 26 76 65 72 69 66 69 65 72 3d ?? ?? ?? 26 63 61 6d 70 61 69 67 6e 3d } //5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*5) >=26
 
}