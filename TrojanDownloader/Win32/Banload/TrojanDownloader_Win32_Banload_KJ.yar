
rule TrojanDownloader_Win32_Banload_KJ{
	meta:
		description = "TrojanDownloader:Win32/Banload.KJ,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 0e 00 00 "
		
	strings :
		$a_03_0 = {68 00 00 0a 00 6a 00 6a 00 68 ?? 00 00 00 6a ?? 6a 00 6a 00 ?? 6a 00 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? (6a 00|68 ?? ?? ??) ?? 90 03 02 06 6a 64 68 ?? ?? 00 00 6a 00 a1 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? eb 0c } //10
		$a_01_1 = {75 72 8b 16 8b c2 89 45 ec 8b 45 ec 85 c0 74 05 83 e8 04 8b 00 83 f8 03 7e 4e } //2
		$a_03_2 = {74 50 6a 00 8d 55 ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 75 ?? ff 75 fc b8 ?? ?? ?? ?? 8d 55 ?? e8 ?? ?? ?? ?? ff 75 ?? 8d 45 ?? ba 03 00 00 00 } //2
		$a_03_3 = {7e 4f bf 01 00 00 00 8b 45 fc 0f b6 5c 38 ff 80 fb 5c 75 24 ff 75 f8 8d 45 ?? 8b d3 e8 } //2
		$a_03_4 = {50 68 00 04 00 00 8d 85 ?? ?? ff ff 50 56 e8 ?? ?? ?? ?? 6a 00 8d 95 ?? ?? ff ff 8b 4d ?? 8d 85 ?? ?? ff ff e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 7d ?? 00 75 c9 } //2
		$a_01_5 = {5a 3a 5c 44 72 6f 70 62 6f 78 5c 4d 79 20 44 72 6f 70 62 6f 78 5c 50 72 6f 6a 65 74 6f 73 5c 4a 61 76 61 6e } //2 Z:\Dropbox\My Dropbox\Projetos\Javan
		$a_01_6 = {3a 49 4e 49 43 49 4f } //1 :INICIO
		$a_01_7 = {44 45 4c 41 50 50 20 45 4c 53 45 20 47 4f 54 4f 20 44 45 4c 42 41 54 } //1 DELAPP ELSE GOTO DELBAT
		$a_01_8 = {3a 44 45 4c 41 50 50 } //1 :DELAPP
		$a_01_9 = {3a 44 45 4c 42 41 54 } //1 :DELBAT
		$a_01_10 = {53 68 61 72 65 64 41 50 50 73 22 3d 2d } //1 SharedAPPs"=-
		$a_01_11 = {4e 45 54 20 53 54 41 52 54 20 57 6d 69 41 70 73 72 76 33 32 00 } //1
		$a_01_12 = {49 4e 4f 56 41 4e 44 4f 4f 4f 4f 2e 2e 2e 00 } //1
		$a_01_13 = {32 33 38 37 37 34 39 31 31 00 } //1 ㌲㜸㐷ㄹ1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2+(#a_03_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=12
 
}