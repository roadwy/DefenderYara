
rule TrojanDownloader_Win32_Zlob_gen_AJ{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!AJ,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 56 69 64 65 6f 41 63 63 65 73 73 43 6f 64 65 63 } //1 Software\Microsoft\Windows\CurrentVersion\Uninstall\VideoAccessCodec
		$a_00_1 = {2f 6f 63 78 2f 56 69 64 65 6f 41 63 63 65 73 73 43 6f 64 65 63 2e 6f 63 78 } //1 /ocx/VideoAccessCodec.ocx
		$a_00_2 = {5c 56 69 64 65 6f 41 63 63 65 73 73 43 6f 64 65 63 5c 56 69 64 65 6f 41 63 63 65 73 73 43 6f 64 65 63 2e 6f 63 78 } //1 \VideoAccessCodec\VideoAccessCodec.ocx
		$a_02_3 = {64 65 6c 20 2f 53 20 2f 51 20 76 70 6e 90 01 03 2e 65 78 65 90 00 } //1
		$a_00_4 = {64 65 6c 20 2f 46 20 2f 51 20 69 6d 65 78 2e 62 61 74 } //1 del /F /Q imex.bat
		$a_00_5 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 57 } //1 InternetOpenW
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}