
rule TrojanDownloader_Win32_Phorpiex_APX_MTB{
	meta:
		description = "TrojanDownloader:Win32/Phorpiex.APX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 55 fc 8b 45 cc 2b 42 14 8b 4d fc 03 41 0c 2b 45 f8 8b 55 d4 89 42 28 8b 45 d4 c7 40 08 ad de 00 00 6a 00 8b 4d f8 51 ff 15 ?? ?? ?? ?? 8b 55 f8 52 ff 15 ?? ?? ?? ?? 8b 45 f4 50 } //3
		$a_01_1 = {25 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 25 00 5c 00 77 00 69 00 6e 00 64 00 72 00 78 00 2e 00 74 00 78 00 74 00 } //2 %appdata%\windrx.txt
		$a_01_2 = {4d 00 65 00 4e 00 6f 00 74 00 5f 00 2e 00 74 00 78 00 74 00 } //1 MeNot_.txt
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}