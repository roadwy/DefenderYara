
rule TrojanDownloader_Win32_Zojectdow_STA{
	meta:
		description = "TrojanDownloader:Win32/Zojectdow.STA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 83 c0 01 89 45 f4 81 7d f4 ?? ?? ?? ?? 7d 19 8b 4d ec 03 4d f4 0f be 11 81 f2 ?? ?? ?? ?? 8b 45 ec 03 45 f4 88 10 eb } //1
		$a_02_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 00 00 00 00 00 00 00 00 [0-a0] 63 65 72 74 2e 63 6f 6d 2f 44 69 67 69 43 65 72 74 41 73 73 75 72 65 64 49 44 52 6f 6f 74 43 41 2e 63 72 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}