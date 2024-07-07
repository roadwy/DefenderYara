
rule TrojanDownloader_Win32_Teginim_A{
	meta:
		description = "TrojanDownloader:Win32/Teginim.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 37 57 ff 75 f4 8d 85 d8 f6 ff ff 50 ff 75 ec e8 84 fe ff ff 83 c4 10 83 f8 ff 75 03 33 f6 46 } //3
		$a_01_1 = {2f 6d 69 6e 69 2f 67 65 74 2e 70 68 70 3f 69 64 3d } //1 /mini/get.php?id=
		$a_01_2 = {25 73 6b 6d 71 25 64 2e 65 78 65 } //1 %skmq%d.exe
		$a_01_3 = {5f 63 6c 73 25 64 2e 62 61 74 } //1 _cls%d.bat
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}