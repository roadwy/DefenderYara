
rule TrojanDownloader_Win32_Small_NCC{
	meta:
		description = "TrojanDownloader:Win32/Small.NCC,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //10 WriteProcessMemory
		$a_01_1 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //10 CreateRemoteThread
		$a_02_2 = {55 8b ec 83 c4 ec e8 90 01 02 00 00 8d 4d fc 51 6a 20 50 e8 90 01 02 00 00 c7 45 ec 01 00 00 00 8d 45 f0 50 68 90 01 02 40 00 6a 00 e8 90 01 02 00 00 c7 45 f8 02 00 00 00 6a 00 6a 00 6a 10 90 00 } //10
		$a_00_3 = {69 64 3d 25 73 26 70 3d 25 73 26 6d 62 3d 25 64 26 6a 31 3d 25 73 2e 26 7a 31 3d 25 73 26 64 31 3d 25 73 26 73 72 76 3d 25 73 } //1 id=%s&p=%s&mb=%d&j1=%s.&z1=%s&d1=%s&srv=%s
		$a_00_4 = {69 64 3d 25 73 26 70 3d 25 73 26 6c 63 6b 3d 25 73 26 6d 62 3d 25 73 26 71 3d 25 73 26 73 72 76 3d 25 73 } //1 id=%s&p=%s&lck=%s&mb=%s&q=%s&srv=%s
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_02_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=31
 
}