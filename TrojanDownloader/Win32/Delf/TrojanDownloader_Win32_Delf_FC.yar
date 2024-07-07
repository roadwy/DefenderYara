
rule TrojanDownloader_Win32_Delf_FC{
	meta:
		description = "TrojanDownloader:Win32/Delf.FC,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {46 55 43 4b 2e 2e 2e 2e 46 55 43 4b 2e 2e 2e 2e 46 55 43 4b 2e 2e 2e 2e 46 55 43 4b 2e 2e 2e 2e } //10 FUCK....FUCK....FUCK....FUCK....
		$a_00_2 = {68 74 74 70 3a 2f 2f 73 33 31 2e 63 6e 7a 7a 2e 63 6f 6d 2f 73 74 61 74 2e 70 68 70 3f 69 64 3d } //10 http://s31.cnzz.com/stat.php?id=
		$a_02_3 = {73 76 63 68 6f 73 74 2e 65 78 65 90 02 09 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 53 70 6f 6f 6c 65 72 5c 53 74 61 72 74 90 00 } //2
		$a_00_4 = {63 6c 61 73 73 65 73 2e 73 79 73 00 00 } //1
		$a_00_5 = {57 69 6e 53 76 63 45 78 00 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_02_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=33
 
}