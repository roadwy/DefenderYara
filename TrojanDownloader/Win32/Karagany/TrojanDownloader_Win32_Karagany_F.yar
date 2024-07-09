
rule TrojanDownloader_Win32_Karagany_F{
	meta:
		description = "TrojanDownloader:Win32/Karagany.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4f 70 65 72 61 2f 90 10 02 00 2e 90 0f 02 00 20 50 (|72) 65 73 74 6f 2f } //1
		$a_03_1 = {21 23 4c 44 52 ?? ?? ?? 2e 62 61 74 } //1
		$a_03_2 = {b9 e8 03 00 00 f7 f1 3d 58 02 00 00 76 ?? 68 b4 05 00 00 } //1
		$a_01_3 = {8b 51 04 83 ea 08 d1 ea 89 55 f4 8b 45 08 83 c0 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}