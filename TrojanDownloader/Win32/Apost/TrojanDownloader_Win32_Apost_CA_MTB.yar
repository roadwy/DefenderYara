
rule TrojanDownloader_Win32_Apost_CA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Apost.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c 5c 31 37 32 38 2e 69 63 6f 2e 6c 6f 67 2e 76 62 73 } //01 00  %USERPROFILE%\\1728.ico.log.vbs
		$a_01_1 = {49 6e 73 74 61 6c 6c 50 61 74 68 3d 22 25 54 45 4d 50 25 22 } //01 00  InstallPath="%TEMP%"
		$a_01_2 = {55 70 6c 6f 61 64 53 74 72 69 6e 67 28 27 68 74 74 70 3a 2f 2f 62 69 6e 74 6f 72 73 2e 72 75 2f 67 65 74 2e 70 68 70 27 2c 27 27 29 } //01 00  UploadString('http://bintors.ru/get.php','')
		$a_01_3 = {25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c 6e 74 75 73 65 72 2e 74 78 74 } //01 00  %USERPROFILE%\ntuser.txt
		$a_01_4 = {21 40 49 6e 73 74 61 6c 6c 45 6e 64 40 21 } //01 00  !@InstallEnd@!
		$a_01_5 = {53 65 6c 66 44 65 6c 65 74 65 3d 22 31 22 } //00 00  SelfDelete="1"
	condition:
		any of ($a_*)
 
}