
rule Backdoor_Win32_Kirts_A{
	meta:
		description = "Backdoor:Win32/Kirts.A,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 08 00 00 "
		
	strings :
		$a_01_0 = {0f b7 4d 10 99 f7 f9 0f b6 54 15 c8 8b 45 0c 0f be 08 33 d1 8b 45 0c 88 10 8b 4d 0c 83 c1 01 89 4d 0c e9 37 ff ff ff } //20
		$a_01_1 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 4d 61 6e 61 67 65 72 2e 62 61 74 } //5 shellexecute=Manager.bat
		$a_01_2 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 4d 61 6e 61 67 65 72 2e 76 62 73 } //5 shellexecute=Manager.vbs
		$a_01_3 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 4d 61 6e 61 67 65 72 2e 6a 73 } //5 shellexecute=Manager.js
		$a_01_4 = {74 61 73 6b 6c 69 73 74 20 2f 46 49 20 22 49 4d 41 47 45 4e 41 4d 45 20 65 71 20 77 69 6e 6d 67 72 2e 65 78 65 } //1 tasklist /FI "IMAGENAME eq winmgr.exe
		$a_01_5 = {28 4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 68 74 74 70 3a 2f 2f 25 73 2f 74 2e 65 78 65 27 } //1 (New-Object Net.WebClient).DownloadFile('http://%s/t.exe'
		$a_01_6 = {43 4d 44 20 2f 43 20 74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d 20 25 73 } //1 CMD /C taskkill /F /IM %s
		$a_01_7 = {6f 62 6a 2e 72 75 6e 28 22 44 65 76 69 63 65 4d 61 6e 61 67 65 72 2e 62 61 74 22 2c 20 30 29 3b } //1 obj.run("DeviceManager.bat", 0);
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=31
 
}