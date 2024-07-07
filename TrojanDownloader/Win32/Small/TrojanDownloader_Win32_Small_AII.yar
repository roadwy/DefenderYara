
rule TrojanDownloader_Win32_Small_AII{
	meta:
		description = "TrojanDownloader:Win32/Small.AII,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 10 8a 54 24 14 53 55 8b c1 2b f1 8b ef 8a 1c 06 32 da 88 18 40 4d 75 f5 5d c6 04 0f 00 } //1
		$a_01_1 = {4e 65 66 6b 68 65 55 3c 3e 38 48 4d 3d 3d 31 24 38 4f 3f 30 24 3d 3e 6d 3c 24 48 4c 4a 38 24 4d 3c 4c 48 3b 3b 3a 3d 3d 39 30 4b } //1 NefkheU<>8HM==1$8O?0$=>m<$HLJ8$M<LH;;:==90K
		$a_01_2 = {31 3d 3e 3c 27 3e 3e 39 3a 39 3d 38 3b 3a 27 6a 67 } //1 1=><'>>9:9=8;:'jg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_Win32_Small_AII_2{
	meta:
		description = "TrojanDownloader:Win32/Small.AII,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {70 6c 6d 64 3b 24 69 70 6f 69 77 73 78 73 64 66 } //1 plmd;$ipoiwsxsdf
		$a_00_1 = {5c 73 79 73 6f 70 74 69 6f 6e 2e 69 6e 69 } //1 \sysoption.ini
		$a_00_2 = {5c 5f 75 6e 69 6e 73 74 61 6c 6c } //1 \_uninstall
		$a_00_3 = {5c 74 6d 70 2e 65 78 65 2e 74 6d 70 } //1 \tmp.exe.tmp
		$a_00_4 = {32 2e 74 6d 70 } //1 2.tmp
		$a_00_5 = {6b 74 76 2e 6c 6e 6b } //1 ktv.lnk
		$a_02_6 = {4d 53 43 46 90 01 38 74 6d 70 2e 65 78 65 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_02_6  & 1)*1) >=7
 
}