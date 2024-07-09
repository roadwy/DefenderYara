
rule TrojanDownloader_Win32_Bancos_FC{
	meta:
		description = "TrojanDownloader:Win32/Bancos.FC,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {5c 69 69 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 \iiexplorer.exe
		$a_00_1 = {64 00 6c 00 2e 00 64 00 72 00 6f 00 70 00 62 00 6f 00 78 00 2e 00 63 00 6f 00 6d 00 2f 00 75 00 2f 00 } //1 dl.dropbox.com/u/
		$a_00_2 = {2f 00 47 00 65 00 74 00 44 00 69 00 73 00 6b 00 53 00 65 00 72 00 69 00 61 00 6c 00 2e 00 64 00 6c 00 6c 00 } //1 /GetDiskSerial.dll
		$a_00_3 = {2f 00 69 00 69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 6a 00 73 00 } //1 /iiexplorer.js
		$a_02_4 = {77 00 2e 00 66 00 75 00 6e 00 6f 00 72 00 70 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 66 00 6f 00 74 00 6f 00 73 00 2f 00 [0-18] 2e 00 6a 00 70 00 67 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}