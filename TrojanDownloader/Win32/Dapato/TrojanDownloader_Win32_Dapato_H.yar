
rule TrojanDownloader_Win32_Dapato_H{
	meta:
		description = "TrojanDownloader:Win32/Dapato.H,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 00 65 00 74 00 20 00 57 00 72 00 69 00 74 00 65 00 53 00 74 00 75 00 66 00 66 00 20 00 3d 00 20 00 46 00 53 00 59 00 2e 00 4f 00 70 00 65 00 6e 00 54 00 65 00 78 00 74 00 46 00 69 00 6c 00 65 00 28 00 41 00 4c 00 59 00 59 00 20 00 26 00 20 00 56 00 52 00 46 00 59 00 2c 00 20 00 38 00 2c 00 20 00 54 00 72 00 75 00 65 00 29 00 } //1 Set WriteStuff = FSY.OpenTextFile(ALYY & VRFY, 8, True)
		$a_00_1 = {5c 00 6d 00 73 00 64 00 64 00 6e 00 2e 00 76 00 62 00 73 00 } //1 \msddn.vbs
		$a_02_2 = {8b 08 ff 51 7c 8d 55 b0 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 45 b0 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 b0 } //1
		$a_00_3 = {46 6f 72 20 69 20 3d 20 31 20 54 6f 20 4c 65 6e 42 28 20 4f 42 48 2e 52 65 73 70 6f 6e 73 65 42 6f 64 79 20 29 } //1 For i = 1 To LenB( OBH.ResponseBody )
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}