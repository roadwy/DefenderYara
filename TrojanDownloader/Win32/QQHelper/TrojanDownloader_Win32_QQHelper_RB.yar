
rule TrojanDownloader_Win32_QQHelper_RB{
	meta:
		description = "TrojanDownloader:Win32/QQHelper.RB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {3d 45 3d 4d 3d 62 3d 6d 3d } //1 =E=M=b=m=
		$a_01_1 = {55 70 64 61 74 65 72 75 6e 2e 65 78 65 } //1 Updaterun.exe
		$a_01_2 = {22 25 73 5c 72 75 6e 64 6c 6c 66 72 6f 6d 77 69 6e 32 30 30 30 2e 65 78 65 22 20 22 25 73 5c 77 62 65 6d 5c 25 73 2e 64 6c 6c 22 2c 45 78 70 6f 72 74 20 40 69 6e 73 74 61 6c 6c } //1 "%s\rundllfromwin2000.exe" "%s\wbem\%s.dll",Export @install
		$a_01_3 = {25 2e 38 58 25 2e 34 58 25 2e 34 58 25 2e 32 58 25 2e 32 58 25 2e 32 58 25 2e 32 58 25 2e 32 58 25 2e 32 58 25 2e 32 58 25 2e 32 58 } //1 %.8X%.4X%.4X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X
		$a_01_4 = {6d 69 63 72 6f 73 6f 66 74 5c 5c 44 69 72 65 63 74 33 64 5c 5c 64 69 6e 70 75 74 5c 5c 75 70 64 61 74 65 } //2 microsoft\\Direct3d\\dinput\\update
		$a_01_5 = {2e 74 71 7a 6e 2e 63 6f 6d 2f 62 61 72 62 69 6e 64 73 6f 66 74 2f 62 61 72 73 65 74 75 70 2e 65 78 65 } //2 .tqzn.com/barbindsoft/barsetup.exe
		$a_01_6 = {5c 74 65 6d 70 2e 65 78 65 } //1 \temp.exe
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1) >=5
 
}