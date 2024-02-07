
rule Trojan_Win32_Musecador_V_MTB{
	meta:
		description = "Trojan:Win32/Musecador.V!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 31 00 32 00 33 00 2e 00 62 00 61 00 74 00 } //01 00  C:\123.bat
		$a_01_1 = {72 65 67 20 61 64 64 20 22 68 6b 6c 6d 5c 73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 20 6e 74 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 49 6d 61 67 65 20 46 69 6c 65 20 45 78 65 63 75 74 69 6f 6e 20 4f 70 74 69 6f 6e 73 5c 5a 68 75 44 6f 6e 67 46 61 6e 67 59 75 2e 65 78 65 22 20 2f 76 20 64 65 62 75 67 67 65 72 20 2f 74 20 72 65 67 5f 73 7a 20 2f 64 20 22 6e 74 73 64 20 2d 64 22 20 2f 66 } //01 00  reg add "hklm\software\microsoft\windows nt\currentversion\Image File Execution Options\ZhuDongFangYu.exe" /v debugger /t reg_sz /d "ntsd -d" /f
		$a_01_2 = {72 65 67 20 61 64 64 20 22 68 6b 6c 6d 5c 73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 20 6e 74 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 49 6d 61 67 65 20 46 69 6c 65 20 45 78 65 63 75 74 69 6f 6e 20 4f 70 74 69 6f 6e 73 5c 33 36 30 74 72 61 79 2e 65 78 65 22 20 2f 76 20 64 65 62 75 67 67 65 72 20 2f 74 20 72 65 67 5f 73 7a 20 2f 64 20 22 6e 74 73 64 20 2d 64 22 20 2f 66 } //01 00  reg add "hklm\software\microsoft\windows nt\currentversion\Image File Execution Options\360tray.exe" /v debugger /t reg_sz /d "ntsd -d" /f
		$a_01_3 = {72 65 67 20 61 64 64 20 22 68 6b 6c 6d 5c 73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 20 6e 74 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 49 6d 61 67 65 20 46 69 6c 65 20 45 78 65 63 75 74 69 6f 6e 20 4f 70 74 69 6f 6e 73 5c 74 61 73 6b 6d 67 72 2e 65 78 65 22 20 2f 76 20 64 65 62 75 67 67 65 72 20 2f 74 20 72 65 67 5f 73 7a 20 2f 64 20 22 6e 74 73 64 20 2d 64 22 20 2f 66 } //01 00  reg add "hklm\software\microsoft\windows nt\currentversion\Image File Execution Options\taskmgr.exe" /v debugger /t reg_sz /d "ntsd -d" /f
		$a_01_4 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 61 00 73 00 73 00 6f 00 63 00 20 00 2e 00 74 00 78 00 74 00 20 00 3d 00 20 00 65 00 78 00 65 00 66 00 69 00 6c 00 65 00 } //01 00  cmd.exe /c assoc .txt = exefile
		$a_01_5 = {76 00 69 00 72 00 75 00 73 00 20 00 51 00 51 00 20 00 36 00 32 00 31 00 33 00 37 00 30 00 39 00 30 00 32 00 } //00 00  virus QQ 621370902
	condition:
		any of ($a_*)
 
}