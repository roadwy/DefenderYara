
rule TrojanSpy_Win64_FauxperKeylogger{
	meta:
		description = "TrojanSpy:Win64/FauxperKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 0b 00 00 01 00 "
		
	strings :
		$a_80_0 = {4c 4c 6f 67 67 65 72 46 69 6c 65 20 3d 20 73 76 68 6f 73 74 2e 65 78 65 } //LLoggerFile = svhost.exe  01 00 
		$a_80_1 = {4c 55 70 6c 6f 61 64 65 72 46 69 6c 65 20 3d 20 73 70 6f 6f 6c 73 76 63 2e 65 78 65 } //LUploaderFile = spoolsvc.exe  01 00 
		$a_80_2 = {4c 43 6f 72 65 46 69 6c 65 20 3d 20 65 78 70 6c 6f 72 65 72 73 2e 65 78 65 } //LCoreFile = explorers.exe  01 00 
		$a_80_3 = {4b 65 79 62 64 20 68 6f 6f 6b 3a 20 25 73 } //Keybd hook: %s  01 00 
		$a_80_4 = {57 69 6e 64 6f 77 53 70 79 2e 61 68 6b 20 6f 72 20 41 55 33 5f 53 70 79 2e 65 78 65 } //WindowSpy.ahk or AU3_Spy.exe  01 00 
		$a_80_5 = {43 6f 72 65 46 69 6c 65 4c 69 73 74 20 3d 20 25 52 43 6f 72 65 46 69 6c 65 25 7c 25 4c 4c 6f 67 67 65 72 46 69 6c 65 25 7c 25 4c 55 70 6c 6f 61 64 65 72 46 69 6c 65 25 7c 25 4c 43 6f 72 65 46 69 6c 65 25 } //CoreFileList = %RCoreFile%|%LLoggerFile%|%LUploaderFile%|%LCoreFile%  01 00 
		$a_80_6 = {70 77 62 2e 73 69 6c 65 6e 74 20 3a 3d 20 74 72 75 65 } //pwb.silent := true  01 00 
		$a_80_7 = {70 77 62 2e 64 6f 63 75 6d 65 6e 74 2e 61 6c 6c 2e 53 75 62 6d 69 74 2e 43 6c 69 63 6b 28 29 } //pwb.document.all.Submit.Click()  01 00 
		$a_80_8 = {53 56 49 20 3d 20 53 79 73 74 65 6d 20 56 6f 6c 75 6d 65 20 49 6e 66 6f 72 6d 61 74 69 6f 6e } //SVI = System Volume Information  01 00 
		$a_02_9 = {43 00 6f 00 72 00 65 00 20 00 3d 00 20 00 4b 00 61 00 73 00 70 00 65 00 72 00 73 00 6b 00 79 00 90 02 20 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 90 00 } //01 00 
		$a_02_10 = {43 6f 72 65 20 3d 20 4b 61 73 70 65 72 73 6b 79 90 02 20 53 65 63 75 72 69 74 79 90 00 } //00 00 
		$a_00_11 = {5d 04 00 } //00 fc 
	condition:
		any of ($a_*)
 
}