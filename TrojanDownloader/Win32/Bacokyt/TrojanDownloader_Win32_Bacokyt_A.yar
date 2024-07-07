
rule TrojanDownloader_Win32_Bacokyt_A{
	meta:
		description = "TrojanDownloader:Win32/Bacokyt.A,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 70 69 6e 6c 74 7a 73 6f 66 74 77 61 72 65 6c 74 64 61 2e 69 6e 66 6f 2f 73 6b 79 68 64 74 76 2d 64 72 69 76 65 67 65 6e 69 6f 73 30 34 2f 41 70 69 53 6f 63 6b 65 74 36 34 42 79 74 65 73 2e 62 63 6b } //10 spinltzsoftwareltda.info/skyhdtv-drivegenios04/ApiSocket64Bytes.bck
		$a_01_1 = {6d 61 69 73 75 6d 61 76 65 7a 63 6f 6e 74 61 2e 69 6e 66 6f 2f 65 73 63 72 69 74 61 2f } //6 maisumavezconta.info/escrita/
		$a_01_2 = {5c 41 76 61 73 74 68 69 73 74 6f 72 79 00 00 00 ff ff ff ff 0a 00 00 00 63 6f 6e 74 61 64 6f 72 } //4
		$a_01_3 = {61 73 68 51 75 69 63 6b 2e 65 78 65 } //2 ashQuick.exe
		$a_01_4 = {26 44 65 74 65 63 74 41 6e 74 69 56 69 72 75 73 3d } //2 &DetectAntiVirus=
		$a_01_5 = {26 47 65 74 57 69 6e 56 65 72 73 69 6f 6e 41 73 53 74 72 69 6e 67 57 69 6e 41 72 63 68 3d } //2 &GetWinVersionAsStringWinArch=
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*6+(#a_01_2  & 1)*4+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=14
 
}