
rule TrojanDownloader_Win32_Small_BKU{
	meta:
		description = "TrojanDownloader:Win32/Small.BKU,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {ff 35 8a 3e 00 10 e8 ?? 08 00 00 c3 55 8b ec 68 e8 03 00 00 e8 ?? 08 00 00 6a 00 6a 00 e8 ?? 09 00 00 0b c0 74 30 6a ?? 6a 01 e8 ?? 02 00 00 0b c0 74 0c 68 00 50 00 10 e8 ?? 05 00 00 eb 17 6a ?? 6a 02 e8 ?? 02 00 00 0b c0 74 0a 68 ?? 50 00 10 e8 ?? 05 00 00 e8 ?? 06 00 00 68 c0 27 09 00 e8 } //1
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 43 4c 53 49 44 5c 25 73 5c 49 6e 50 72 6f 63 53 65 72 76 65 72 33 32 } //1 SOFTWARE\Classes\CLSID\%s\InProcServer32
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c 25 73 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\%s
		$a_02_3 = {68 74 74 70 3a 2f 2f [0-30] 2e 70 68 70 3f 69 64 3d 25 73 26 76 65 72 3d } //1
		$a_00_4 = {62 65 6e 73 6f 72 74 79 2e 64 6c 6c } //1 bensorty.dll
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}