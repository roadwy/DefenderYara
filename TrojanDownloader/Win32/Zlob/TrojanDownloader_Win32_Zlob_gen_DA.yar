
rule TrojanDownloader_Win32_Zlob_gen_DA{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!DA,SIGNATURE_TYPE_PEHSTR_EXT,2a 00 2a 00 09 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //10 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 } //10 Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
		$a_01_2 = {70 79 77 61 72 65 } //10 pyware
		$a_01_3 = {6f 6f 6c 2e 63 6f 6d 2f 72 65 } //10 ool.com/re
		$a_00_4 = {03 c8 40 89 44 24 10 8a 04 0a 32 44 24 20 88 01 49 ff 4c 24 10 75 } //1
		$a_02_5 = {33 f5 c1 ee 02 46 81 ff ?? ?? ?? 00 89 74 24 10 75 ?? ff 15 } //1
		$a_00_6 = {7b 33 42 37 41 41 45 42 31 2d 39 46 33 44 2d 34 34 39 31 2d 39 43 30 36 2d 43 37 31 36 35 43 41 38 44 30 35 38 7d } //1 {3B7AAEB1-9F3D-4491-9C06-C7165CA8D058}
		$a_00_7 = {7b 39 30 33 34 41 35 32 33 2d 44 30 36 38 2d 34 42 45 38 2d 41 32 38 34 2d 39 44 46 32 37 38 42 45 37 37 36 45 7d } //1 {9034A523-D068-4BE8-A284-9DF278BE776E}
		$a_00_8 = {7b 44 41 45 44 39 32 36 36 2d 38 43 32 38 2d 34 43 31 43 2d 38 42 35 38 2d 35 43 36 36 45 46 46 31 44 33 30 32 7d } //1 {DAED9266-8C28-4C1C-8B58-5C66EFF1D302}
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_00_4  & 1)*1+(#a_02_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=42
 
}