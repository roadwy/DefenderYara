
rule TrojanDownloader_Win32_Delfildr_A{
	meta:
		description = "TrojanDownloader:Win32/Delfildr.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 00 ff d3 8d 45 ec 8b 4d fc ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 ec 8b 45 08 8b 40 fc e8 ?? ?? ?? ?? 33 c0 5a 59 59 64 89 10 } //1
		$a_03_1 = {c7 45 a0 44 00 00 00 66 c7 45 d0 05 00 c7 45 cc 01 00 00 00 84 db 74 ?? 8d 45 e4 50 8d 45 a0 50 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? 8b 45 fc e8 ?? ?? ?? ?? 50 ff d7 } //1
		$a_00_2 = {73 65 74 57 65 61 74 68 65 72 43 69 74 79 3e } //1 setWeatherCity>
		$a_00_3 = {66 75 63 6b 33 36 30 63 6e 6d } //1 fuck360cnm
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}