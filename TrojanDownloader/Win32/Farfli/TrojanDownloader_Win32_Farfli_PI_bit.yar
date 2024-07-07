
rule TrojanDownloader_Win32_Farfli_PI_bit{
	meta:
		description = "TrojanDownloader:Win32/Farfli.PI!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a 04 0a 34 90 01 01 88 01 41 4e 75 f5 90 00 } //1
		$a_03_1 = {e8 0f 12 00 00 99 b9 90 01 04 f7 f9 80 c2 90 01 01 88 54 34 90 01 01 46 81 fe 90 01 04 7c e3 90 00 } //1
		$a_01_2 = {25 73 5c 25 73 5c 64 61 74 5c 25 64 25 64 } //1 %s\%s\dat\%d%d
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 68 6f 73 74 } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}