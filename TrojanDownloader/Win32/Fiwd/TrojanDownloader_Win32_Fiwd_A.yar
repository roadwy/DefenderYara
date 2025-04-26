
rule TrojanDownloader_Win32_Fiwd_A{
	meta:
		description = "TrojanDownloader:Win32/Fiwd.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {6a 00 c1 ee 06 ff d7 83 c4 04 8b f8 ff 15 ?? ?? ?? ?? 03 f8 57 ff 15 [0-0a] ff d5 99 b9 c0 5d 00 00 f7 f9 } //1
		$a_00_1 = {68 51 46 00 00 c7 44 24 18 51 46 00 00 } //1
		$a_00_2 = {50 4f 53 54 00 00 00 00 57 69 6e 64 6f 77 73 4d 61 6e 61 67 65 72 00 } //1
		$a_00_3 = {73 6f 63 6b 73 2e 65 78 65 00 74 69 6d 65 00 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}