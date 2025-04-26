
rule Worm_Win32_Usbwatch_B{
	meta:
		description = "Worm:Win32/Usbwatch.B,SIGNATURE_TYPE_PEHSTR,22 00 22 00 07 00 00 "
		
	strings :
		$a_01_0 = {55 53 42 57 41 54 43 48 50 52 4f } //10 USBWATCHPRO
		$a_01_1 = {25 73 5c 41 75 74 6f 52 75 6e 2e 69 6e 66 } //10 %s\AutoRun.inf
		$a_01_2 = {25 53 79 73 74 65 6d 44 72 69 76 65 25 5c 52 45 43 59 43 4c 45 } //10 %SystemDrive%\RECYCLE
		$a_01_3 = {4e 6f 44 72 69 76 65 54 79 70 65 41 75 74 6f 52 75 6e } //1 NoDriveTypeAutoRun
		$a_01_4 = {53 68 6f 77 53 75 70 65 72 48 69 64 64 65 6e } //1 ShowSuperHidden
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 } //1 Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced
		$a_01_6 = {36 34 35 46 46 30 34 30 2d 35 30 38 31 2d 31 30 31 42 2d 39 46 30 38 2d 30 30 41 41 30 30 32 46 39 35 34 45 } //1 645FF040-5081-101B-9F08-00AA002F954E
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=34
 
}