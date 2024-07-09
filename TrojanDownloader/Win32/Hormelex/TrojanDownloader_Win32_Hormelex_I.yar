
rule TrojanDownloader_Win32_Hormelex_I{
	meta:
		description = "TrojanDownloader:Win32/Hormelex.I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {64 89 20 33 c9 b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d8 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 ba ?? ?? ?? ?? 8b c3 8b 08 ff 51 30 8d 45 fc b9 ?? ?? ?? ?? 8b 15 } //1
		$a_03_1 = {63 68 61 6d 31 30 31 30 [0-20] 2e 7a 69 70 } //1
		$a_01_2 = {39 41 42 37 36 35 38 44 41 39 35 31 38 43 34 34 46 44 32 33 31 33 33 33 44 31 37 36 } //1 9AB7658DA9518C44FD231333D176
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}