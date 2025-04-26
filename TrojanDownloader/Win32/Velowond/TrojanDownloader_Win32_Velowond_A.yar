
rule TrojanDownloader_Win32_Velowond_A{
	meta:
		description = "TrojanDownloader:Win32/Velowond.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {83 c6 02 53 68 ?? ?? ?? ?? 8d 4d e8 89 75 c4 e8 ?? ?? ?? ?? 8b f0 8d 4d e8 8d 7e 01 57 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 4d d4 89 45 10 e8 ?? ?? ?? ?? 8d 4d d8 c6 45 fc 09 } //2
		$a_01_1 = {25 74 65 6d 70 70 61 74 68 25 } //1 %temppath%
		$a_01_2 = {25 77 69 6e 70 61 74 68 25 } //1 %winpath%
		$a_01_3 = {25 73 79 73 74 65 6d 70 61 74 68 25 } //1 %systempath%
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}