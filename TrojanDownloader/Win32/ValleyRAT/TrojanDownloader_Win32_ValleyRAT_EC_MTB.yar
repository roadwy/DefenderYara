
rule TrojanDownloader_Win32_ValleyRAT_EC_MTB{
	meta:
		description = "TrojanDownloader:Win32/ValleyRAT.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 33 d2 f7 75 14 8b 45 10 0f b6 0c 10 8b 55 08 03 55 fc 0f b6 02 33 c1 8b 4d 08 03 4d fc 88 01 } //10
		$a_01_1 = {4e 00 54 00 55 00 53 00 45 00 52 00 2e 00 44 00 58 00 4d } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}
rule TrojanDownloader_Win32_ValleyRAT_EC_MTB_2{
	meta:
		description = "TrojanDownloader:Win32/ValleyRAT.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {50 72 6f 63 65 73 73 4b 69 6c 6c 65 72 } //1 ProcessKiller
		$a_81_1 = {72 75 6e 61 73 } //1 runas
		$a_81_2 = {5a 68 75 44 6f 6e 67 46 61 6e 67 59 75 } //1 ZhuDongFangYu
		$a_81_3 = {53 6f 66 74 4d 67 72 4c 69 74 65 } //1 SoftMgrLite
		$a_81_4 = {44 75 6d 70 55 70 65 72 } //1 DumpUper
		$a_81_5 = {57 69 6e 72 61 72 } //1 Winrar
		$a_81_6 = {73 61 66 65 73 76 72 } //1 safesvr
		$a_81_7 = {57 49 4e 57 4f 52 44 2e 65 78 65 } //1 WINWORD.exe
		$a_81_8 = {77 77 6c 69 62 2e 64 6c 6c } //1 wwlib.dll
		$a_81_9 = {78 69 67 2e 70 70 74 } //1 xig.ppt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}