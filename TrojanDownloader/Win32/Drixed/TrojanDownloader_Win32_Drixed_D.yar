
rule TrojanDownloader_Win32_Drixed_D{
	meta:
		description = "TrojanDownloader:Win32/Drixed.D,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {c7 40 08 f7 28 9e 50 } //2
		$a_03_1 = {ef be ad de eb 90 09 01 00 90 17 02 01 01 bf be } //2
		$a_03_2 = {8d 78 10 8b 45 ?? 8b 55 ?? 33 07 33 57 04 83 65 0c 00 } //2
		$a_03_3 = {52 00 65 00 64 00 69 00 72 00 65 00 63 00 74 00 45 00 58 00 45 00 [0-0a] 25 00 4c 00 4f 00 43 00 41 00 4c 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 25 00 4c 00 6f 00 77 00 5c 00 ?? ?? ?? ?? ?? ?? 2e 00 62 00 61 00 74 00 } //1
		$a_01_4 = {53 3a 5c 57 6f 72 6b 5c 5f 62 69 6e 5c 52 65 6c 65 61 73 65 2d 57 69 6e 33 32 5c 6c 6f 61 64 65 72 2e 70 64 62 } //1 S:\Work\_bin\Release-Win32\loader.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}