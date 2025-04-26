
rule Trojan_Win32_Killav_BS{
	meta:
		description = "Trojan:Win32/Killav.BS,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 53 53 8d 45 ?? 6a 04 50 68 4b e1 22 00 } //1
		$a_03_1 = {8b 51 04 8d 41 08 89 45 08 89 5d ?? 8d 42 f8 89 5d fc d1 e8 89 45 ?? 74 43 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Killav_BS_2{
	meta:
		description = "Trojan:Win32/Killav.BS,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {63 6d 64 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 73 63 61 6e 66 72 6d 2e 65 78 65 } //1 cmd /c taskkill /im scanfrm.exe
		$a_00_1 = {63 6d 64 20 2f 63 20 63 61 63 6c 73 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 20 2f 65 20 2f 70 20 65 76 65 72 79 6f 6e 65 3a 66 } //1 cmd /c cacls c:\windows\system32 /e /p everyone:f
		$a_00_2 = {63 6d 64 20 2f 63 20 73 63 20 63 6f 6e 66 69 67 20 65 6b 72 6e 20 73 74 61 72 74 3d 20 64 69 73 61 62 6c 65 64 } //1 cmd /c sc config ekrn start= disabled
		$a_00_3 = {63 6d 64 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 65 6b 72 6e 2e 65 78 65 } //1 cmd /c taskkill /im ekrn.exe
		$a_00_4 = {63 6d 64 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 65 67 75 69 2e 65 78 65 } //1 cmd /c taskkill /im egui.exe
		$a_00_5 = {63 6d 64 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 61 76 70 2e 65 78 65 20 2f 66 } //1 cmd /c taskkill /im avp.exe /f
		$a_01_6 = {6a 00 50 ff d3 68 88 13 00 00 ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}