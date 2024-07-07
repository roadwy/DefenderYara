
rule TrojanDownloader_Win32_Renos_DJ{
	meta:
		description = "TrojanDownloader:Win32/Renos.DJ,SIGNATURE_TYPE_PEHSTR,29 00 28 00 07 00 00 "
		
	strings :
		$a_01_0 = {2f 6c 6f 67 33 2e 70 68 70 3f 74 6d 3d 25 64 } //10 /log3.php?tm=%d
		$a_01_1 = {4f 53 3a 25 64 2e 25 64 2c 20 42 4c 44 3a 25 64 2c } //10 OS:%d.%d, BLD:%d,
		$a_01_2 = {42 78 4c 6f 61 64 65 72 2e 4c 6f 61 64 65 72 } //10 BxLoader.Loader
		$a_01_3 = {27 25 41 50 50 49 44 25 27 20 3d 20 73 20 27 41 78 4c 6f 61 64 65 72 27 } //10 '%APPID%' = s 'AxLoader'
		$a_01_4 = {73 00 63 00 61 00 6e 00 65 00 72 00 } //1 scaner
		$a_01_5 = {77 77 77 2e 77 69 6e 69 66 69 78 65 72 2e 63 6f 6d } //10 www.winifixer.com
		$a_01_6 = {41 63 74 69 76 65 4c 6f 61 64 65 72 20 56 } //10 ActiveLoader V
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10) >=40
 
}