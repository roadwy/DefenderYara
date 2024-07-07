
rule Trojan_Win32_Harnbrush_A{
	meta:
		description = "Trojan:Win32/Harnbrush.A,SIGNATURE_TYPE_PEHSTR,10 00 10 00 08 00 00 "
		
	strings :
		$a_01_0 = {66 74 70 3a 2f 2f 62 72 75 73 68 79 3a 62 72 75 73 68 79 } //4 ftp://brushy:brushy
		$a_01_1 = {2e 6d 61 69 6c 68 75 6e 74 2e 63 6e 2f 62 72 75 73 68 } //4 .mailhunt.cn/brush
		$a_01_2 = {2e 69 6e 69 00 00 00 47 65 74 50 72 69 76 61 74 65 50 72 6f 66 69 6c 65 49 6e 74 } //4
		$a_01_3 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 2d 2d 2d 49 45 58 50 4c 4f 52 45 2e 45 58 45 } //2 CreateProcess---IEXPLORE.EXE
		$a_01_4 = {6d 6f 6e 69 2e 64 6c 6c 5f 49 6e 69 74 54 73 6b 48 65 61 64 } //2 moni.dll_InitTskHead
		$a_01_5 = {53 61 76 65 49 45 50 72 6f 63 65 73 73 49 44 } //2 SaveIEProcessID
		$a_01_6 = {42 72 6f 77 73 65 72 46 72 61 6d 65 47 72 69 70 70 65 72 43 6c 61 73 73 } //1 BrowserFrameGripperClass
		$a_01_7 = {53 65 6e 64 4d 73 67 20 41 74 20 30 5f } //1 SendMsg At 0_
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=16
 
}