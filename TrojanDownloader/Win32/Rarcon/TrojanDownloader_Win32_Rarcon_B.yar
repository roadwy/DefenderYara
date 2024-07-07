
rule TrojanDownloader_Win32_Rarcon_B{
	meta:
		description = "TrojanDownloader:Win32/Rarcon.B,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 0c 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 57 69 6e 52 41 52 } //10 SOFTWARE\WinRAR
		$a_01_1 = {63 64 66 31 39 31 32 2e 74 6d 70 } //10 cdf1912.tmp
		$a_01_2 = {77 69 6e 72 61 72 5f 63 6f 6e 66 69 67 2e 74 6d 70 } //10 winrar_config.tmp
		$a_01_3 = {44 3a 5c 56 6f 6c 75 6d 65 44 48 } //2 D:\VolumeDH
		$a_01_4 = {5c 74 61 6f } //1 \tao
		$a_01_5 = {74 75 61 6e 2e 69 63 6f } //1 tuan.ico
		$a_01_6 = {6e 65 74 2e 65 78 65 } //1 net.exe
		$a_01_7 = {5c 69 6e 6a 2e } //1 \inj.
		$a_01_8 = {2e 77 61 76 } //1 .wav
		$a_01_9 = {73 74 61 72 74 2f 6d 69 6e } //1 start/min
		$a_01_10 = {75 64 61 74 65 } //1 udate
		$a_01_11 = {75 6e 61 6d 65 } //1 uname
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=23
 
}