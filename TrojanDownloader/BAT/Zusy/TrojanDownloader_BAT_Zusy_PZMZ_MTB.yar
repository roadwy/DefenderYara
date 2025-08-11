
rule TrojanDownloader_BAT_Zusy_PZMZ_MTB{
	meta:
		description = "TrojanDownloader:BAT/Zusy.PZMZ!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 43 3a 5c } //3 Add-MpPreference -ExclusionPath C:\
		$a_01_1 = {24 6f 75 74 70 75 74 20 3d 20 22 24 65 6e 76 3a 54 65 6d 70 2f 52 75 6e 74 69 6d 65 42 72 6f 6b 65 72 2e 65 78 65 } //2 $output = "$env:Temp/RuntimeBroker.exe
		$a_01_2 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 50 6f 77 65 72 53 68 65 6c 6c 20 2d 56 65 72 62 20 52 75 6e 41 73 20 22 2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 43 6f 6d 6d 61 6e 64 } //1 Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command
		$a_01_3 = {47 65 74 43 75 72 72 65 6e 74 28 29 29 2e 49 73 49 6e 52 6f 6c 65 28 5b 53 65 63 75 72 69 74 79 2e 50 72 69 6e 63 69 70 61 6c 2e 57 69 6e 64 6f 77 73 42 75 69 6c 74 49 6e 52 6f 6c 65 5d 3a 3a 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 } //1 GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}