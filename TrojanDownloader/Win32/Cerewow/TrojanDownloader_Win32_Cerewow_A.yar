
rule TrojanDownloader_Win32_Cerewow_A{
	meta:
		description = "TrojanDownloader:Win32/Cerewow.A,SIGNATURE_TYPE_PEHSTR_EXT,2a 00 2a 00 09 00 00 "
		
	strings :
		$a_01_0 = {2f 6c 61 6e 64 69 6e 67 3f 61 63 74 69 6f 6e 3d 72 65 70 6f 72 74 } //1 /landing?action=report
		$a_01_1 = {2f 6c 61 6e 64 69 6e 67 3f 61 63 74 69 6f 6e 3d 70 69 6e 67 } //1 /landing?action=ping
		$a_01_2 = {2f 6c 61 6e 64 69 6e 67 3f 61 63 74 69 6f 6e 3d 66 69 6c 65 } //1 /landing?action=file
		$a_01_3 = {2f 6c 61 6e 64 69 6e 67 3f 61 63 74 69 6f 6e 3d 6a 73 66 69 6c 65 26 73 79 73 74 65 6d 68 61 73 68 3d 25 73 26 } //1 /landing?action=jsfile&systemhash=%s&
		$a_01_4 = {73 79 73 74 65 6d 69 6e 6a 65 63 74 65 64 } //10 systeminjected
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 4d 49 43 52 4f 53 4f 46 54 5c 57 49 4e 44 4f 57 53 5c 43 55 52 52 45 4e 54 20 56 45 52 53 49 4f 4e 5c 52 55 4e } //10 SOFTWARE\MICROSOFT\WINDOWS\CURRENT VERSION\RUN
		$a_01_6 = {69 73 6e 65 74 32 30 69 6e 73 74 } //10 isnet20inst
		$a_01_7 = {25 57 49 4e 44 49 52 25 2f 74 65 6d 70 2f 31 2e 74 78 74 } //10 %WINDIR%/temp/1.txt
		$a_01_8 = {33 31 2e 31 38 34 2e 31 39 34 2e 39 39 } //10 31.184.194.99
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*10) >=42
 
}