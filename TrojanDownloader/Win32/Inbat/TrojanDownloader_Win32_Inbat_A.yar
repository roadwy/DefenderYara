
rule TrojanDownloader_Win32_Inbat_A{
	meta:
		description = "TrojanDownloader:Win32/Inbat.A,SIGNATURE_TYPE_PEHSTR,08 00 08 00 0d 00 00 "
		
	strings :
		$a_01_0 = {25 4d 59 46 49 4c 45 53 25 5c 55 70 64 2e 65 78 65 } //3 %MYFILES%\Upd.exe
		$a_01_1 = {25 4d 59 46 49 4c 45 53 25 5c 69 6e 2e 65 78 65 } //3 %MYFILES%\in.exe
		$a_01_2 = {2f 2f 77 77 77 2e 78 75 6e 6c 65 69 31 30 30 2e 63 6f 6d 2f 6d 73 6e 2f } //3 //www.xunlei100.com/msn/
		$a_01_3 = {2f 2f 69 6e 73 74 61 6c 6c 2e 78 69 6e 72 75 69 63 6e 2e 63 6f 6d } //3 //install.xinruicn.com
		$a_01_4 = {2f 2f 74 6f 32 2e 35 63 6e 64 2e 63 6f 6d 2f } //3 //to2.5cnd.com/
		$a_01_5 = {2f 2f 61 2e 78 77 78 69 61 7a 61 69 2e 63 6f 6d 2f } //3 //a.xwxiazai.com/
		$a_01_6 = {2f 62 69 62 69 62 65 69 } //1 /bibibei
		$a_01_7 = {2f 63 6f 6f 70 65 6e 5f 73 65 74 75 70 5f } //1 /coopen_setup_
		$a_01_8 = {70 69 70 69 5c 75 6e 69 6e 73 30 30 30 2e 65 78 65 22 20 2f 66 } //1 pipi\unins000.exe" /f
		$a_01_9 = {2f 44 44 48 59 54 2e 65 78 65 } //1 /DDHYT.exe
		$a_01_10 = {2f 70 69 70 69 5f 64 61 65 5f } //1 /pipi_dae_
		$a_01_11 = {2f 6b 75 67 6f 75 5f } //1 /kugou_
		$a_01_12 = {2f 33 36 61 31 31 2e 65 78 65 } //1 /36a11.exe
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=8
 
}