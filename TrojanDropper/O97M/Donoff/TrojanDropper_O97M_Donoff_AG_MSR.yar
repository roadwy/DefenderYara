
rule TrojanDropper_O97M_Donoff_AG_MSR{
	meta:
		description = "TrojanDropper:O97M/Donoff.AG!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 08 00 00 "
		
	strings :
		$a_80_0 = {75 75 20 3d 20 22 43 3a 5c 55 73 65 72 73 5c 22 20 2b 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 55 73 65 72 4e 61 6d 65 20 2b 20 22 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 44 6e 73 53 79 73 74 65 6d 2e 65 78 65 22 } //uu = "C:\Users\" + Application.UserName + "\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\DnsSystem.exe"  2
		$a_80_1 = {61 72 72 53 70 6c 69 74 53 74 72 69 6e 67 73 31 30 20 3d 20 53 70 6c 69 74 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 54 65 78 74 42 6f 78 31 2e 56 61 6c 75 65 2c 20 22 2c 22 29 } //arrSplitStrings10 = Split(ActiveDocument.TextBox1.Value, ",")  1
		$a_80_2 = {61 72 72 53 70 6c 69 74 53 74 72 69 6e 67 73 32 28 69 29 20 3d 20 52 65 70 6c 61 63 65 28 61 72 72 53 70 6c 69 74 53 74 72 69 6e 67 73 31 30 28 69 29 2c } //arrSplitStrings2(i) = Replace(arrSplitStrings10(i),  1
		$a_80_3 = {66 69 6c 65 4e 6d 62 20 3d 20 46 72 65 65 46 69 6c 65 } //fileNmb = FreeFile  1
		$a_80_4 = {50 75 74 20 23 66 69 6c 65 4e 6d 62 2c 20 31 2c 20 61 72 72 53 70 6c 69 74 53 74 72 69 6e 67 73 32 } //Put #fileNmb, 1, arrSplitStrings2  1
		$a_80_5 = {53 75 62 20 41 75 74 6f 43 6c 6f 73 65 28 29 } //Sub AutoClose()  1
		$a_80_6 = {73 74 72 46 69 6c 65 45 78 69 73 74 73 20 3d 20 44 69 72 28 75 75 29 } //strFileExists = Dir(uu)  1
		$a_80_7 = {4f 70 65 6e 20 75 75 20 46 6f 72 20 42 69 6e 61 72 79 20 41 63 63 65 73 73 20 57 72 69 74 65 20 41 73 20 23 66 69 6c 65 4e 6d 62 } //Open uu For Binary Access Write As #fileNmb  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=9
 
}
rule TrojanDropper_O97M_Donoff_AG_MSR_2{
	meta:
		description = "TrojanDropper:O97M/Donoff.AG!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 46 75 6e 63 74 69 6f 6e 20 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 22 } //1 Private Declare Function VirtualProtect Lib "kernel32" Alias "VirtualProtect"
		$a_01_1 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 46 75 6e 63 74 69 6f 6e 20 4b 69 6c 6c 54 69 6d 65 72 20 4c 69 62 20 22 75 73 65 72 33 32 22 20 41 6c 69 61 73 20 22 4b 69 6c 6c 54 69 6d 65 72 22 } //1 Private Declare Function KillTimer Lib "user32" Alias "KillTimer"
		$a_01_2 = {63 6f 6e 74 65 6e 74 20 3d 20 62 79 74 65 73 68 65 78 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 43 6f 6d 70 61 6e 79 22 29 2e 56 61 6c 75 65 29 } //1 content = byteshex(ActiveDocument.BuiltInDocumentProperties("Company").Value)
		$a_01_3 = {2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 43 61 74 65 67 6f 72 79 22 29 2e 56 61 6c 75 65 29 } //1 .BuiltInDocumentProperties("Category").Value)
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 20 73 68 65 6c 6c 43 6f 64 65 2c 20 4c 65 6e 67 74 68 2c 20 36 34 2c 20 56 61 72 50 74 72 28 76 29 } //1 VirtualProtect shellCode, Length, 64, VarPtr(v)
		$a_01_5 = {47 65 74 4f 62 6a 65 63 74 28 22 6e 65 77 3a 46 39 33 35 44 43 32 32 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42 22 29 2e 45 6e 76 69 72 6f 6e 6d 65 6e 74 28 22 50 72 6f 63 65 73 73 22 29 28 22 7b 46 43 46 32 33 38 32 41 2d 34 44 44 37 2d 34 46 42 45 2d 39 45 37 37 2d 30 45 45 33 44 44 36 36 33 37 39 41 7d 22 29 20 3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 46 75 6c 6c 4e 61 6d 65 } //1 GetObject("new:F935DC22-1CF0-11D0-ADB9-00C04FD58A0B").Environment("Process")("{FCF2382A-4DD7-4FBE-9E77-0EE3DD66379A}") = ActiveDocument.FullName
		$a_01_6 = {28 22 7b 31 46 37 39 41 45 45 37 2d 37 46 36 35 2d 34 42 38 30 2d 41 31 43 36 2d 45 35 43 39 30 41 37 42 45 36 43 46 7d 22 29 20 3d 20 22 } //1 ("{1F79AEE7-7F65-4B80-A1C6-E5C90A7BE6CF}") = "
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}