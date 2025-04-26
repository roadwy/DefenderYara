
rule TrojanDownloader_Win32_Kolilks_A{
	meta:
		description = "TrojanDownloader:Win32/Kolilks.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {ff d6 6a 2b 99 59 f7 f9 83 c2 30 83 fa 39 7e 05 83 fa 41 7c eb } //1
		$a_03_1 = {68 ff 7f 00 00 6a 01 68 ?? ?? ?? ?? ff 15 90 09 03 00 74 1d (56|57) } //1
		$a_03_2 = {3d a8 08 00 00 74 ?? 3d e8 02 00 00 75 } //1
		$a_03_3 = {6a 7c 8d 4d 08 e8 ?? ?? ?? ?? 83 c3 04 81 fb ?? ?? ?? ?? 8b ?? 7c b7 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*10) >=11
 
}